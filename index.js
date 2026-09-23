import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const BASE = "https://indico.cern.ch";
const UA = "openclaw-indico-plugin/0.3";
const DOWNLOAD_DIR = join(homedir(), ".openclaw", "workspace", "indico-files");

// Indico PAT (indp_...) as Bearer works for both /api/* and /export/*
// once the token's scope includes Classic API — verified against
// /export/categ/2.json, /export/event/*.json, /export/room/*.
// Token source: 0600 file ~/openclaw/indicotoken. INDICO_TOKEN also lives in
// the gateway vault (allow-host indico.cern.ch) as the authoritative store.
// plugins.entries.<id>.config SecretRefs are NOT resolved for local plugins on
// this OpenClaw version (gen14 probe: register() received the raw
// {source,provider,id} object), unlike channels.* and provider auth profiles
// where the gateway core resolves refs. So the file is the delivery path here.
const TOKEN_PATH = join(homedir(), ".openclaw", "creds", "gateway", "indico-token");
function getToken() {
  return readFileSync(TOKEN_PATH, "utf8").trim();
}

function authHeaders(extra) {
  return Object.assign(
    { "User-Agent": UA, Authorization: "Bearer " + getToken() },
    extra || {},
  );
}

async function indicoGet(pathWithQuery) {
  const res = await fetch(BASE + pathWithQuery, { headers: authHeaders() });
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (_) {}
  return { status: res.status, ok: res.ok, parsed, text };
}

// Binary file download: /export/event/E/session/S/contrib/C/subcontrib/SC/material/M/R.bin
async function indicoDownload(path) {
  const res = await fetch(BASE + path, { headers: authHeaders(), redirect: "follow" });
  const buf = Buffer.from(await res.arrayBuffer());
  const contentType = res.headers.get("content-type") || "application/octet-stream";
  if (!res.ok) {
    const preview = buf.toString("utf8", 0, Math.min(buf.length, 400));
    return { ok: false, status: res.status, preview };
  }
  mkdirSync(DOWNLOAD_DIR, { recursive: true });
  const safeName = path.split("/").filter(Boolean).join("_").replace(/[^A-Za-z0-9._-]/g, "_");
  const out = join(DOWNLOAD_DIR, safeName);
  writeFileSync(out, buf);
  return { ok: true, status: res.status, path: out, bytes: buf.length, contentType };
}

// Generic send to Indico management ("UI") endpoints: form or JSON body,
// XHR header so validate_on_submit returns JSON instead of a full page.
// WARNING: these are Indico's internal UI JSON endpoints (used by the web
// frontend, reverse-engineered from the indico source) — NOT the documented
// read-only export API. They are version-coupled and may change on upgrades.
async function indicoSend(path, method, body) {
  const opts = { method, headers: authHeaders({ "X-Requested-With": "XMLHttpRequest" }) };
  if (body && body.json) {
    opts.headers = authHeaders({ "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json" });
    opts.body = JSON.stringify(body.json);
  } else if (body && body.form) {
    opts.headers = authHeaders({ "X-Requested-With": "XMLHttpRequest", "Content-Type": "application/x-www-form-urlencoded" });
    const usp = new URLSearchParams();
    for (const [k, v] of body.form) usp.append(k, v);
    opts.body = usp.toString();
  }
  const res = await fetch(BASE + path, opts);
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (_) {}
  return { status: res.status, ok: res.ok, parsed, text };
}

function protectionPath(p) {
  if (p.object_type === "event") return `/event/${p.event_id}/manage/protection`;
  if (p.object_type === "session") return `/event/${p.event_id}/manage/sessions/${p.object_id}/protection`;
  return `/event/${p.event_id}/manage/contributions/${p.object_id}/protection`;
}

// Indico's ACL widgets persist only _signed_ principals ("User:<id>:<b64>.<sig>",
// or Email:<...>:<sig>). Unsigned identifiers are silently dropped on write without a 4xx
// (post 200 тверд echoing a re-rendered form), so callers MUST supply the signed
// strings returned by indico_search_users — never invent them locally.
function baseUserId(foss) {
  if (foss == null) return null;
  if (typeof foss === 'string') {
    const m = /^User:(\d+)(?::|$)/.exec(foss);
    return m ? m[1] : null;
  }
  if (typeof foss === 'object') return baseUserId(foss.identifier ?? (foss.id != null ? String(foss.id) : null));
  return null;
}

function assertSignedIdentifier(s, label) {
  if (typeof s !== 'string' || !s.includes(':') || !/^(User|Email|Group|IPGroup):.+:/.test(s)) {
    throw new Error(
      `${label || 'identifier'} '${String(s).slice(0, 60)}' is not a signed principal identifier. ` +
      'Call indico_search_users first and pass the `identifier` field it returns verbatim.'
    );
  }
}


function htmlUnescape(s) {
  return s.replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// GET the protection page/dialog and parse the persisted ACL out of the
// permissions widget input value + the checked protection_mode radio.
// Event page returns full HTML; session/contribution return JSON {html, js}.
// FAILS LOUDLY on login redirect/403 — callers must not clobber ACLs blind.
async function aclRead(path) {
  const res = await fetch(BASE + path, { headers: authHeaders({ "X-Requested-With": "XMLHttpRequest" }), redirect: "manual" });
  const text = await res.text();
  if (res.status >= 300 && res.status < 400) throw new Error("acl read redirected (login) HTTP " + res.status);
  if (!res.ok) throw new Error("acl read HTTP " + res.status + ": " + text.slice(0, 200));
  let html = text;
  try {
    const j = JSON.parse(text);
    html = String(j.html || "") + " " + (Array.isArray(j.js) ? j.js.join(" ") : String(j.js || ""));
  } catch (_) {}
  if (/class="login-pf"|id="login-form"/.test(html)) throw new Error("acl read hit the SSO login page (no manage access?)");
  // IMPORTANT: extract the value attr from the RAW html first — it contains
  // &quot; entities that must stay escaped until extraction (else the inner
  // quote truncates the match), then unescape the extracted value.
  const rawHtml = html;
  html = htmlUnescape(html);
  const tagRe = /<input[^>]*name="permissions"[^>]*>/g;
  let value = null;
  for (const t of rawHtml.match(tagRe) || []) {
    const m = t.match(/value=("[^"]*"|'[^']*')/);
    if (m) {
      value = htmlUnescape(m[1].slice(1, -1));
      break;
    }
  }
  let entries = [];
  if (value != null && value !== "") {
    try { entries = JSON.parse(value); } catch (e) { throw new Error("acl value JSON parse failed: " + e.message + " value=" + JSON.stringify(value.slice(0, 200))); }
  }
  let mode = null;
  const radios = html.match(/<input[^>]*name="protection_mode"[^>]*>/g) || [];
  for (const r of radios) {
    if (/checked/.test(r)) {
      const vm = r.match(/value="(\w+)"/);
      if (vm) mode = vm[1];
    }
  }
  return { status: res.status, entries, protection_mode: mode };
}

// POST form (room booking create)
async function indicoPostForm(path, params) {
  const body = new URLSearchParams(params).toString();
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/x-www-form-urlencoded" }),
    body,
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (_) {}
  return { status: res.status, ok: res.ok, parsed, text };
}

function render(r) {
  if (r.parsed == null) return r.text.slice(0, 2000);
  return JSON.stringify(r.parsed, null, 2).slice(0, 6000);
}

function okResult(text, details) {
  return { content: [{ type: "text", text }], details: Object.assign({ ok: true }, details) };
}
function errResult(text, details) {
  return { content: [{ type: "text", text }], details: Object.assign({ ok: false }, details) };
}

function makeGetTool(name, description, buildPath, paramSchema) {
  return {
    name,
    description,
    parameters: paramSchema,
    async execute(_id, p) {
      const r = await indicoGet(buildPath(p || {}));
      if (!r.ok) {
        return errResult("Indico HTTP " + r.status + ": " + r.text.slice(0, 300), { status: r.status });
      }
      return okResult(render(r), { status: r.status });
    },
  };
}

function esc(s) { return encodeURIComponent(String(s)); }

// Indico accepts ISO dates or today/yesterday/tomorrow/+NdHHhMMm offsets.
const dateLike = "^(\\d{4}-\\d{2}-\\d{2}|today|tomorrow|yesterday|[+-]\\d+d\\d{0,2}h?\\d{0,2}m?)$";

export default {
  register(api) {
    // ---- /api/user/ ------------------------------------------------------
    api.registerTool(makeGetTool(
      "indico_user",
      "Whoami for the Indico API token — returns the owning account profile.",
      () => "/api/user/",
      { type: "object", properties: {}, additionalProperties: false },
    ));

    // ---- /export/user/{id}.json ------------------------------------------
    api.registerTool(makeGetTool(
      "indico_user_details",
      "Public profile of an Indico user. Param: user_id (int).",
      (p) => `/export/user/${p.user_id}.json`,
      {
        type: "object",
        additionalProperties: false,
        properties: { user_id: { type: "integer", minimum: 0 } },
        required: ["user_id"],
      },
    ));

    // ---- /export/event/search/{TERM}.json --------------------------------
    api.registerTool(makeGetTool(
      "indico_search_events",
      "Search Indico events. Params: q (query text, required), from/to (YYYY-MM-DD or today/tomorrow), limit (max 100).",
      (p) => {
        const parts = ["occ=yes", `limit=${p.limit ?? 25}`];
        parts.push(`from=${p.from ? esc(p.from) : "today"}`);
        parts.push(`to=${p.to ? esc(p.to) : "today"}`);
        return `/export/event/search/${esc(p.q)}.json?` + parts.join("&");
      },
      {
        type: "object",
        additionalProperties: false,
        properties: {
          q: { type: "string", description: "search term" },
          from: { type: "string", pattern: dateLike },
          to: { type: "string", pattern: dateLike },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["q"],
      },
    ));

    // ---- /export/categ/{id}.json ------------------------------------------
    api.registerTool(makeGetTool(
      "indico_category_events",
      "List events in an Indico category. Params: category_id (int), from/to, limit.",
      (p) => {
        const parts = [`limit=${p.limit ?? 25}`, "occ=yes"];
        parts.push(`from=${p.from ? esc(p.from) : "today"}`);
        parts.push(`to=${p.to ? esc(p.to) : "today"}`);
        if (p.detail) parts.push(`detail=${esc(p.detail)}`);
        return `/export/categ/${p.category_id}.json?` + parts.join("&");
      },
      {
        type: "object",
        additionalProperties: false,
        properties: {
          category_id: { type: "integer", minimum: 0 },
          from: { type: "string", pattern: dateLike },
          to: { type: "string", pattern: dateLike },
          limit: { type: "integer", minimum: 1, maximum: 100 },
          detail: { type: "string", enum: ["events", "contributions"] },
        },
        required: ["category_id"],
      },
    ));

    // ---- /export/event/{id}.json ------------------------------------------
    api.registerTool(makeGetTool(
      "indico_event_details",
      "Detailed info about one Indico event. Params: event_id (int), detail (events|contributions|subcontributions|sessions|minutes), from/to, occ.",
      (p) => {
        const parts = [];
        parts.push(`occ=${p.occ === false ? "no" : "yes"}`);
        if (p.detail) parts.push(`detail=${esc(p.detail)}`);
        if (p.from) parts.push(`from=${esc(p.from)}`);
        if (p.to) parts.push(`to=${esc(p.to)}`);
        return `/export/event/${p.event_id}.json?` + parts.join("&");
      },
      {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          detail: {
            type: "string",
            enum: ["events", "contributions", "subcontributions", "sessions", "minutes"],
            description: "contributions=full timetable contributions; sessions=session blocks; minutes=notes",
          },
          from: { type: "string", pattern: dateLike },
          to: { type: "string", pattern: dateLike },
          occ: { type: "boolean", description: "include occurrences (default true)" },
        },
        required: ["event_id"],
      },
    ));

    // ---- /export/timetable/{id}.json --------------------------------------
    api.registerTool(makeGetTool(
      "indico_timetable",
      "Timetable of an event (scheduled contributions/breaks/blocks). Param: event_id (int).",
      (p) => `/export/timetable/${p.event_id}.json`,
      {
        type: "object",
        additionalProperties: false,
        properties: { event_id: { type: "integer", minimum: 0 } },
        required: ["event_id"],
      },
    ));

    // ---- /export/event/.../material/... file download ---------------------
    api.registerTool({
      name: "indico_download_file",
      description:
        "Download an Indico attachment (slide deck, minutes, ...) to local disk. " +
        "Params: event_id, material_id, resource_id required; session_id/contribution_id/subcontribution_id optional narrowing path segments. " +
        "material_id may be a default-group name such as 'Slides'. Returns saved file path.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          session_id: { type: "integer", minimum: 0 },
          contribution_id: { type: "integer", minimum: 0 },
          subcontribution_id: { type: "integer", minimum: 0 },
          material_id: { type: "string", description: "material name (e.g. Slides) or material id" },
          resource_id: { type: "string", description: "resource id of the file" },
        },
        required: ["event_id", "material_id", "resource_id"],
      },
      async execute(_id, p) {
        const segs = ["", "export", "event", String(p.event_id)];
        if (p.session_id != null) segs.push("session", String(p.session_id));
        if (p.contribution_id != null) segs.push("contrib", String(p.contribution_id));
        if (p.subcontribution_id != null) segs.push("subcontrib", String(p.subcontribution_id));
        segs.push("material", esc(p.material_id), esc(p.resource_id) + ".bin");
        const r = await indicoDownload(segs.join("/"));
        if (!r.ok) {
          return errResult("Indico download failed HTTP " + r.status + ": " + (r.preview || "").slice(0, 300), { status: r.status });
        }
        return okResult(
          JSON.stringify({ saved: r.path, bytes: r.bytes, contentType: r.contentType }),
          { status: r.status, path: r.path, bytes: r.bytes },
        );
      },
    });

    // ---- /export/room/{loc}/{id}.json --------------------------------------
    api.registerTool(makeGetTool(
      "indico_room_details",
      "Room info or per-room reservations. Params: loc (e.g. CERN), room id (int or dash-separated list), detail (rooms|reservations), from/to.",
      (p) => {
        const parts = [];
        if (p.detail) parts.push(`detail=${esc(p.detail)}`);
        if (p.from) parts.push(`from=${esc(p.from)}`);
        if (p.to) parts.push(`to=${esc(p.to)}`);
        const q = parts.length ? "?" + parts.join("&") : "";
        return `/export/room/${esc(p.loc)}/${esc(String(p.room))}.json` + q;
      },
      {
        type: "object",
        additionalProperties: false,
        properties: {
          loc: { type: "string", description: "room location, e.g. CERN" },
          room: { type: "string", description: "room id; dash-separated list allowed (e.g. '57-63')" },
          detail: { type: "string", enum: ["rooms", "reservations"] },
          from: { type: "string", pattern: dateLike },
          to: { type: "string", pattern: dateLike },
        },
        required: ["loc", "room"],
      },
    ));

    // ---- /export/roomName/{loc}/{name}.json --------------------------------
    api.registerTool(makeGetTool(
      "indico_room_by_name",
      "Look up a room by name, e.g. 'TH Goeppert-Mayer' or building-rooms like '32/1-A24'. Params: loc ('CERN'), name.",
      (p) => `/export/roomName/${esc(p.loc)}/${esc(p.name)}.json`,
      {
        type: "object",
        additionalProperties: false,
        properties: {
          loc: { type: "string" },
          name: { type: "string" },
        },
        required: ["loc", "name"],
      },
    ));

    // ---- /export/reservation/{loc}.json ------------------------------------
    api.registerTool(makeGetTool(
      "indico_reservations",
      "List room bookings (reservations) at a location. Params: from/to, bookedfor (wildcard text), cancelled/rejected/confirmed/archival/recurring/occurrences filters, occurs (comma-separated yyyy-mm-dd).",
      (p) => {
        const parts = ["detail=reservations"];
        if (p.from) parts.push(`from=${esc(p.from)}`); else parts.push("from=today");
        if (p.to) parts.push(`to=${esc(p.to)}`); else parts.push("to=today");
        if (p.bookedfor) parts.push(`bookedfor=${esc(p.bookedfor)}`);
        if (p.occurrences != null) parts.push(`occ=${p.occurrences ? "yes" : "no"}`);
        if (p.cancelled != null) parts.push(`cxl=${p.cancelled ? "yes" : "no"}`);
        if (p.rejected != null) parts.push(`rej=${p.rejected ? "yes" : "no"}`);
        if (p.confirmed) parts.push(`confirmed=${esc(p.confirmed)}`);
        if (p.archival != null) parts.push(`arch=${p.archival ? "yes" : "no"}`);
        if (p.recurring != null) parts.push(`rec=${p.recurring ? "yes" : "no"}`);
        if (p.occurs) parts.push(`occurs=${esc(p.occurs)}`);
        return `/export/reservation/${esc(p.loc || "CERN")}.json?` + parts.join("&");
      },
      {
        type: "object",
        additionalProperties: false,
        properties: {
          loc: { type: "string", description: "location (default CERN)" },
          from: { type: "string", pattern: dateLike },
          to: { type: "string", pattern: dateLike },
          bookedfor: { type: "string", description: "wildcard match on 'booked for' name" },
          occurrences: { type: "boolean" },
          cancelled: { type: "boolean" },
          rejected: { type: "boolean" },
          confirmed: { type: "string", enum: ["yes", "no", "pending"] },
          archival: { type: "boolean" },
          recurring: { type: "boolean" },
          occurs: { type: "string", description: "comma-separated yyyy-mm-dd dates with an occurrence" },
        },
      },
    ));

    // ---- POST /api/roomBooking/bookRoom.json -------------------------------
    api.registerTool({
      name: "indico_book_room",
      description:
        "Create a room booking (WRITE). Params: location ('CERN'), roomid, from/to (YYYY-MM-DDTHH:MM or today/tomorrow/now offsets), reason, username (login the booking is created for). Fails on collision/blocking; pre-booking not possible via this API.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          location: { type: "string" },
          roomid: { type: "string" },
          from: { type: "string", description: "YYYY-MM-DDTHH:MM or 'today'/'tomorrow'/'now'+offset" },
          to: { type: "string" },
          reason: { type: "string" },
          username: { type: "string", description: "login the booking is created for, e.g. bendavid" },
        },
        required: ["location", "roomid", "from", "to", "reason", "username"],
      },
      async execute(_id, p) {
        const r = await indicoPostForm("/api/roomBooking/bookRoom.json", {
          location: p.location,
          roomid: p.roomid,
          from: p.from,
          to: p.to,
          reason: p.reason,
          username: p.username,
        });
        if (!r.ok) {
          return errResult("Indico booking failed HTTP " + r.status + ": " + r.text.slice(0, 400), { status: r.status });
        }
        return okResult(render(r), { status: r.status });
      },
    });

    // ================= WRITE tools (undocumented internal endpoints) ========

    // ---- edit session (title/description/code/duration, keeps others) --------
    api.registerTool({
      name: "indico_edit_session",
      description:
        "Edit a session of an Indico event (WRITE; internal dialog endpoint). Params: event_id, session_id; optional: title, description, code, default_contribution_duration_minutes. " +
        "Unmentioned fields keep their current values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          session_id: { type: "integer", minimum: 0 },
          title: { type: "string" },
          code: { type: "string", description: "BoA session code (conference-only)" },
          description: { type: "string" },
          default_contribution_duration_minutes: { type: "integer", minimum: 1 },
        },
        required: ["event_id", "session_id"],
      },
      async execute(_id, p) {
        let title = p.title;
        if (title == null) {
          const d = await indicoGet(`/export/event/${p.event_id}.json?detail=sessions`);
          const sess = (d.parsed && d.parsed.results && d.parsed.results[0] && d.parsed.results[0].sessions) || [];
          const hit = sess.find((s) => s.id === p.session_id);
          if (!hit) return errResult("no such session", {});
          title = hit.title;
        }
        const form = [
          ["title", String(title)],
          ["description", p.description != null ? p.description : ""],
          ["code", p.code != null ? p.code : ""],
          ["default_contribution_duration", String(p.default_contribution_duration_minutes || 20)],
          ["colors", ""],
          ["location_data", '{"inheriting": true}'],
          ["type", ""],
        ];
        const r = await indicoSend(`/event/${p.event_id}/manage/sessions/${p.session_id}/modify`, "POST", { form });
        if (r.ok && !(r.text || "").includes("alert-error")) {
          return okResult(JSON.stringify({ edited: true, session_id: p.session_id }), { status: r.status });
        }
        return errResult("edit_session failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- delete session ----------------------------------------------------
    api.registerTool({
      name: "indico_delete_session",
      description: "Delete a session of an Indico event (WRITE). Params: event_id, session_id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          session_id: { type: "integer", minimum: 0 },
        },
        required: ["event_id", "session_id"],
      },
      async execute(_id, p) {
        const r = await indicoSend(`/event/${p.event_id}/manage/sessions/${p.session_id}`, "DELETE", {});
        if (r.ok) return okResult(JSON.stringify({ deleted: true, session_id: p.session_id }), { status: r.status });
        return errResult("delete_session failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- delete contribution -------------------------------------------------
    api.registerTool({
      name: "indico_delete_contribution",
      description: "Delete a contribution of an Indico event (WRITE). Params: event_id, contribution_id (real DB id from indico_manage_contributions).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          contribution_id: { type: "integer", minimum: 0 },
        },
        required: ["event_id", "contribution_id"],
      },
      async execute(_id, p) {
        const r = await indicoSend(`/event/${p.event_id}/manage/contributions/${p.contribution_id}`, "DELETE", {});
        if (r.ok) return okResult(JSON.stringify({ deleted: true, contribution_id: p.contribution_id }), { status: r.status });
        return errResult("delete_contribution failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- create event ------------------------------------------------------
    api.registerTool({
      name: "indico_create_event",
      description:
        "Create an Indico event (WRITE; internal UI endpoint). Params: category_id, title, " +
        "event_type (meeting default; lecture needs occurrences — use meeting for simple events), date (YYYY-MM-DD), " +
        "start_time/end_time (HH:MM), timezone (default Europe/Zurich), protection_mode (inheriting default), " +
        "listing (default true). Returns event id and manage URL. NOTE: not a documented Indico API surface — version-coupled.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          category_id: { type: "integer", minimum: 0 },
          title: { type: "string" },
          event_type: { type: "string", enum: ["meeting", "lecture", "conference"], description: "default meeting" },
          date: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$" },
          start_time: { type: "string", pattern: "^\\d{2}:\\d{2}$" },
          end_time: { type: "string", pattern: "^\\d{2}:\\d{2}$" },
          timezone: { type: "string", description: "IANA tz, default Europe/Zurich" },
          protection_mode: { type: "string", enum: ["inheriting", "public", "protected"], description: "default inheriting" },
          listing: { type: "boolean", description: "list in category (default true)" },
        },
        required: ["category_id", "title", "date", "start_time", "end_time"],
      },
      async execute(_id, p) {
        const form = [
          ["event-creation-title", p.title],
          ["event-creation-category", JSON.stringify({ id: p.category_id })],
          ["event-creation-start_dt", p.date],
          ["event-creation-start_dt", p.start_time],
          ["event-creation-end_dt", p.date],
          ["event-creation-end_dt", p.end_time],
          ["event-creation-timezone", p.timezone || "Europe/Zurich"],
          ["event-creation-location_data", "{\"inheriting\": true}"],
          ["event-creation-protection_mode", p.protection_mode || "inheriting"],
          ["event-creation-create_booking", "false"],
          ["event-creation-listing", p.listing === false ? "n" : "y"],
        ];
        const r = await indicoSend(`/event/create/${p.event_type || "meeting"}`, "POST", { form });
        const d = r.parsed;
        if (r.ok && d && d.success && d.redirect) {
          const m = d.redirect.match(/\/event\/(\d+)\//);
          return okResult(JSON.stringify({ created: true, event_id: m ? Number(m[1]) : null, manage_url: BASE + d.redirect }), { status: r.status });
        }
        return errResult("create_event failed HTTP " + r.status + ": " + r.text.slice(0, 400), { status: r.status });
      },
    });

    // ---- search indico users ------------------------------------------
    api.registerTool({
      name: "indico_search_users",
      description:
        "Search Indico users by last name, first name or email (event-scoped search token under the hood). " +
        "Params: q (search text, e.g. a person's surname), and optionally event_id to scope the search (recommended). " +
        "Returns matching users with their Indico user ids — feed those user ids to indico_set_protection.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          q: { type: "string", description: "name or email to search for" },
          event_id: { type: "integer", minimum: 0, description: "scope search to this event (needs to be one the caller may manage)" },
        },
        required: ["q"],
      },
      async execute(_id, p) {
        let tok;
        if (p.event_id != null) {
          tok = await indicoGet(`/user/search/token?event_id=${p.event_id}`);
        } else {
          tok = await indicoGet("/user/search/token");
        }
        if (!tok.ok || !tok.parsed || !tok.parsed.token) {
          return errResult("user-search token failed: HTTP " + tok.status + ": " + (tok.text || "").slice(0, 200), { status: tok.status });
        }
        const q = p.q;
        const isEmail = q.includes("@");
        const params = { token: tok.parsed.token };
        if (isEmail) { params.email = q; params.exact = "1"; }
        else params.last_name = q;
        const srch = await indicoGet("/user/search/?" + new URLSearchParams(params).toString());
        if (!srch.ok || !srch.parsed) {
          return errResult("user search failed: HTTP " + srch.status + ": " + (srch.text || "").slice(0, 200), { status: srch.status });
        }
        const users = (srch.parsed.users || []).map((u) => ({
          id: u.id, full_name: u.full_name, first_name: u.first_name, last_name: u.last_name,
          email: u.email, identifier: u.identifier, affiliation: u.affiliation,
        }));
        return okResult(JSON.stringify({ count: users.length, total: srch.parsed.total, users }, null, 2), { status: srch.status });
      },
    });

    // ---- delete event -------------------------------------------------------
    api.registerTool({
      name: "indico_delete_event",
      description: "Delete an Indico event (WRITE; internal UI endpoint). Param: event_id. Destructive — confirm with the user first.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: { event_id: { type: "integer", minimum: 0 } },
        required: ["event_id"],
      },
      async execute(_id, p) {
        const r = await indicoSend(`/event/${p.event_id}/manage/delete`, "POST", { form: [] });
        if (r.ok && r.parsed && r.parsed.success) return okResult(JSON.stringify({ deleted: true, event_id: p.event_id }), { status: r.status });
        return errResult("delete_event failed HTTP " + r.status + ": " + r.text.slice(0, 300), { status: r.status });
      },
    });

    // ---- create session ------------------------------------------------------
    api.registerTool({
      name: "indico_create_session",
      description:
        "Create a session in an Indico event (WRITE; internal UI endpoint). Params: event_id, title; optional description, " +
        "default_contribution_duration_minutes (default 20), color_background/color_text hex without '#'. Returns new session_id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          title: { type: "string" },
          description: { type: "string" },
          default_contribution_duration_minutes: { type: "integer", minimum: 1 },
          color_background: { type: "string", pattern: "^[0-9a-fA-F]{6}$", description: "hex no #; default 0d316f" },
          color_text: { type: "string", pattern: "^[0-9a-fA-F]{6}$", description: "hex no #; default eff5ff" },
        },
        required: ["event_id", "title"],
      },
      async execute(_id, p) {
        const dur = (p.default_contribution_duration_minutes || 20) * 60;
        const form = [
          ["title", p.title],
          ["description", p.description || ""],
          ["default_contribution_duration", String(dur)],
          ["location_data", "{\"inheriting\": true}"],
          ["colors", JSON.stringify({ background: p.color_background || "0d316f", text: p.color_text || "eff5ff" })],
        ];
        const r = await indicoSend(`/event/${p.event_id}/manage/sessions/create`, "POST", { form });
        const d = r.parsed;
        const sid = d && (d.new_session_id != null ? d.new_session_id : (d.data && d.data.new_session_id));
        if (r.ok && d && d.success && sid != null) {
          return okResult(JSON.stringify({ created: true, session_id: sid }), { status: r.status, session_id: sid });
        }
        return errResult("create_session failed HTTP " + r.status + ": " + r.text.slice(0, 400), { status: r.status });
      },
    });

    // ---- list contributions (management; real DB ids) -------------------------
    api.registerTool({
      name: "indico_manage_contributions",
      description:
        "List an event's contributions from the management view (internal export) with real DB ids, sessions, durations. " +
        "Use this to resolve contribution ids before assign/protect calls. Param: event_id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: { event_id: { type: "integer", minimum: 0 } },
        required: ["event_id"],
      },
      async execute(_id, p) {
        const r = await indicoGet(`/event/${p.event_id}/manage/contributions/contributions.json`);
        if (!r.ok) return errResult("HTTP " + r.status + ": " + r.text.slice(0, 300), { status: r.status });
        const list = (Array.isArray(r.parsed) ? r.parsed : []).map((c) => ({
          id: c.id, friendly_id: c.friendly_id, title: c.title, duration_min: Math.round((c.duration || 0) / 60),
          session: c.session, start_dt: c.start_dt,
        }));
        return okResult(JSON.stringify(list, null, 2).slice(0, 6000), { status: r.status, count: list.length });
      },
    });

    // ---- create contribution --------------------------------------------------
    api.registerTool({
      name: "indico_create_contribution",
      description:
        "Create a contribution in an Indico event (WRITE; internal UI endpoint). Params: event_id, title; optional duration_minutes (default 20), description, keywords (array of strings). " +
        "Newly created contributions are unscheduled; use indico_assign_contribution and indico_schedule_contributions next. Returns the resolved contribution id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          title: { type: "string" },
          description: { type: "string" },
          duration_minutes: { type: "integer", minimum: 1 },
          keywords: { type: "array", items: { type: "string" } },
        },
        required: ["event_id", "title"],
      },
      async execute(_id, p) {
        const form = [
          ["title", p.title],
          ["description", p.description || ""],
          ["duration", String((p.duration_minutes || 20) * 60)],
          ["person_link_data", "[]"],
          ["location_data", "{\"inheriting\": true}"],
          ["references", "[]"],
          ["board_number", ""],
          ["code", ""],
          ["keywords", JSON.stringify(p.keywords || [])],
        ];
        const r = await indicoSend(`/event/${p.event_id}/manage/contributions/create`, "POST", { form });
        if (!(r.ok && r.parsed && r.parsed.success)) {
          return errResult("create_contribution failed HTTP " + r.status + ": " + r.text.slice(0, 400), { status: r.status });
        }
        // resolve the new contribution id via the management listing
        const m = await indicoGet(`/event/${p.event_id}/manage/contributions/contributions.json`);
        let cid = null;
        if (m.ok && Array.isArray(m.parsed)) {
          const matches = m.parsed.filter((c) => c.title === p.title);
          if (matches.length) cid = matches[matches.length - 1].id;
        }
        return okResult(JSON.stringify({ created: true, contribution_id: cid }), { status: r.status, contribution_id: cid });
      },
    });

    // ---- assign contribution to session ----------------------------------------
    api.registerTool({
      name: "indico_assign_contribution",
      description:
        "Assign a contribution to a session (WRITE; PATCH; internal UI endpoint). Params: event_id, contribution_id (real DB id from indico_manage_contributions), session_id (null to unassign).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          contribution_id: { type: "integer", minimum: 0 },
          session_id: { type: ["integer", "null"], minimum: 0 },
        },
        required: ["event_id", "contribution_id", "session_id"],
      },
      async execute(_id, p) {
        const r = await indicoSend(`/event/${p.event_id}/manage/contributions/${p.contribution_id}`, "PATCH", { json: { session_id: p.session_id } });
        if (r.ok) return okResult(JSON.stringify({ assigned: true, contribution_id: p.contribution_id, session_id: p.session_id }), { status: r.status });
        return errResult("assign_contribution failed HTTP " + r.status + ": " + r.text.slice(0, 300), { status: r.status });
      },
    });

    // ---- create session block (empty timetable slot for a session) ------
    api.registerTool({
      name: "indico_create_session_block",
      description:
        "Create an empty session block (a timetable slot) for a session of an event (WRITE; internal XHR endpoint). " +
        "Params: event_id, session_id, day (YYYY-MM-DD), time (HH:MM), duration_minutes (default 60). " +
        "Sessions need a block before contributions in that session can be scheduled; returns the block id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          session_id: { type: "integer", minimum: 0 },
          day: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$" },
          time: { type: "string", pattern: "^\\d{2}:\\d{2}$" },
          duration_minutes: { type: "integer", minimum: 1 },
        },
        required: ["event_id", "session_id", "day", "time"],
      },
      async execute(_id, p) {
        const dur = (p.duration_minutes || 60) * 60;
        const q = `parent_session_id=${p.session_id}&day=${p.day}`;
        const form = [
          ["title", ""], ["code", ""], ["time", p.time], ["duration", String(dur)],
          ["person_links", "[]"], ["location_data", "{\"inheriting\": true}"],
        ];
        const r = await indicoSend(`/event/${p.event_id}/manage/timetable/add-session-block?${q}`, "POST", { form });
        if (r.ok && r.parsed && r.parsed.success && r.parsed.update) {
          const entries = r.parsed.update.entries || {};
          const entry = Object.values(entries)[0] || {};
          return okResult(JSON.stringify({ created: true, block_id: entry.sessionSlotId ?? null, timetable_entry: entry.id ?? null }), { status: r.status });
        }
        return errResult("create_session_block failed HTTP " + r.status + ": " + (r.text || "").slice(0, 300), { status: r.status });
      },
    });

    // ---- edit contribution (title/description/duration) --------------------------
    api.registerTool({
      name: "indico_edit_contribution",
      description:
        "Edit a contribution of an Indico event (WRITE; internal dialog endpoint). Params: event_id, contribution_id; optional: title, description, duration_minutes. " +
        "Unmentioned fields keep their current values (fetched via export first).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          contribution_id: { type: "integer", minimum: 0 },
          title: { type: "string" },
          description: { type: "string" },
          duration_minutes: { type: "integer", minimum: 1 },
        },
        required: ["event_id", "contribution_id"],
      },
      async execute(_id, p) {
        const cur = await indicoGet(`/export/event/${p.event_id}.json?detail=contributions`);
        const contribs = (cur.parsed && cur.parsed.results && cur.parsed.results[0] && cur.parsed.results[0].contributions) || [];
        const hit = contribs.find((c) => c.id === p.contribution_id || c.contributionId === p.contribution_id);
        if (!hit && p.title == null) return errResult("no such contribution", {});
        const title = p.title != null ? p.title : hit.title;
        const description = p.description != null ? p.description : (hit ? hit.description || "" : "");
        const duration = p.duration_minutes != null ? p.duration_minutes : (hit ? Math.round((hit.duration || 1200)) : 30);
        const form = [
          ["title", String(title)],
          ["description", String(description)],
          ["duration", String(duration)],
          ["keywords", "[]"],
          ["person_links", "[]"],
          ["location_data", JSON.stringify({ inheriting: true })],
        ];
        const r = await indicoSend(`/event/${p.event_id}/manage/contributions/${p.contribution_id}/edit`, "POST", { form });
        if (r.ok && !(r.text || "").includes("alert-error")) {
          return okResult(JSON.stringify({ edited: true, contribution_id: p.contribution_id }), { status: r.status });
        }
        return errResult("edit_contribution failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- unschedule contribution (drop timetable entry, keep contribution) ----
    api.registerTool({
      name: "indico_unschedule_contribution",
      description:
        "Remove a contribution from the timetable without deleting it (WRITE; internal REST endpoint). " +
        "Params: event_id, contribution_id.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          contribution_id: { type: "integer", minimum: 0 },
        },
        required: ["event_id", "contribution_id"],
      },
      async execute(_id, p) {
        const d = await indicoGet(`/export/timetable/${p.event_id}.json`);
        const dayMap = (d.parsed && d.parsed.results && d.parsed.results[String(p.event_id)]) || {};
        let entryId = null;
        for (const entries of Object.values(dayMap)) {
          for (const [eid, ent] of Object.entries(entries || {})) {
            const hits = (Object.values(ent.entries || {})).some((c) => String(c.contributionId) === String(p.contribution_id))
              || String(ent.contributionId) === String(p.contribution_id);
            if (hits) { entryId = eid; break; }
          }
          if (entryId) break;
        }
        if (!entryId) return errResult("contribution is not scheduled", {});
        const r = await indicoSend(`/event/${p.event_id}/manage/timetable/${entryId}`, "DELETE", {});
        if (r.ok) return okResult(JSON.stringify({ unscheduled: true, contribution_id: p.contribution_id, entry_id: entryId }), { status: r.status });
        return errResult("unschedule failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- edit timetable entry date/time -----------------------------------
    api.registerTool({
      name: "indico_edit_timetable_entry",
      description:
        "Patch a timetable entry (currently start_dt only; WRITE; internal REST endpoint). Params: event_id, entry_id, start_dt (ISO-8601 with offset).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          entry_id: { type: "integer", minimum: 0 },
          start_dt: { type: "string", description: "ISO-8601 with tz offset" },
        },
        required: ["event_id", "entry_id", "start_dt"],
      },
      async execute(_id, p) {
        const r = await indicoSend(`/event/${p.event_id}/manage/timetable/${p.entry_id}`, "PATCH", { json: { start_dt: p.start_dt } });
        if (r.ok) return okResult(JSON.stringify({ patched: true, entry_id: p.entry_id, start_dt: p.start_dt }), { status: r.status });
        return errResult("edit_timetable_entry failed HTTP " + r.status + ": " + (r.text || "").slice(0, 200), { status: r.status });
      },
    });

    // ---- set protection / ACL ---------------------------------------------------
    api.registerTool({
      name: "indico_set_protection",
      description:
        "Set protection mode and ACL on an Indico object (WRITE; internal UI endpoint; read-then-merge: existing principals are preserved). " +
        "Params: event_id, object_type (event|session|contribution), object_id (omit for event), protection_mode (public|inheriting|protected), " +
        "user_identifiers / manager_identifiers (numeric-or-signed identifiers from indico_search_users, e.g. User:49024:b64.sig). NOTE: undocumented endpoint — version-coupled.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          object_type: { type: "string", enum: ["event", "session", "contribution"] },
          object_id: { type: "integer", minimum: 0 },
          protection_mode: { type: "string", enum: ["public", "inheriting", "protected"], description: "omit to keep current mode" },
          user_identifiers: { type: "array", items: { type: "string" }, description: "signed identifiers from indico_search_users (e.g. User:49024:b64.sig)" },
          manager_identifiers: { type: "array", items: { type: "string" }, description: "signed identifiers from indico_search_users granted full management rights" },
        },
        required: ["event_id", "object_type"],
      },
      async execute(_id, p) {
        const path = protectionPath(p);
        let cur;
        try {
          cur = await aclRead(path);
        } catch (e) {
          return errResult("refusing to write ACL: current state unreadable (" + e.message + ")", {});
        }
        if (p.object_type === "event" && cur.protection_mode == null) {
          return errResult("refusing to write ACL: protection page parsed without a protection_mode (page shape changed or no access)", {});
        }
        const grants = [];
        for (const ident of p.user_identifiers || []) grants.push({ ident, perms: ["_read_access"] });
        for (const ident of p.manager_identifiers || []) grants.push({ ident, perms: ["_full_access"] });
        const signed = [];
        for (const g2 of grants) {
          try { assertSignedIdentifier(g2.ident, g2.perms[0]); } catch (e) { return errResult(e.message, {}); }
          signed.push(g2);
        }
        const grantBase = new Set(signed.map((g2) => baseUserId(g2.ident)).filter(Boolean));
        const kept = (cur.entries || []).filter(([foss]) => !grantBase.has(baseUserId(foss)));
        for (const g2 of signed) kept.push([{ identifier: g2.ident }, g2.perms]);
        const mode = p.protection_mode || cur.protection_mode || "inheriting";
        const r = await indicoSend(path, "POST", { form: [["protection_mode", mode], ["permissions", JSON.stringify(kept)]] });
        const jwin = r.parsed && r.parsed.success;
        const hwin = !r.parsed && r.ok && !/alert-error|form-field-error/.test(r.text);
        if (jwin || hwin) {
          return okResult(JSON.stringify({
            applied: true, object_type: p.object_type, object_id: p.object_id ?? null, mode,
            acl_entries: kept.map(([f, perms]) => ({ id: f.identifier || f, perms })),
          }), { status: r.status });
        }
        return errResult("set_protection failed HTTP " + r.status + ": " + r.text.slice(0, 300), { status: r.status });
      },
    });

    // ---- read protection / ACL --------------------------------------------
    api.registerTool({
      name: "indico_get_protection",
      description:
        "Read protection mode and ACL of an Indico object (internal UI endpoint). Params: event_id, object_type (event|session|contribution), object_id (omit for event). " +
        "Returns kept principals with permission flags: _read_access (can view) or _full_access (management rights).",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          object_type: { type: "string", enum: ["event", "session", "contribution"] },
          object_id: { type: "integer", minimum: 0 },
        },
        required: ["event_id", "object_type"],
      },
      async execute(_id, p) {
        try {
          const res = await aclRead(protectionPath(p));
          return okResult(JSON.stringify({
            object_type: p.object_type, object_id: p.object_id ?? null,
            protection_mode: res.protection_mode,
            acl: res.entries.map(([f, perms]) => ({ id: f.identifier || f, perms })),
          }, null, 2), { status: res.status });
        } catch (e) {
          return errResult("acl read failed: " + e.message, {});
        }
      },
    });

    // ---- schedule contributions into a day --------------------------------------
    api.registerTool({
      name: "indico_schedule_contributions",
      description:
        "Schedule unscheduled contributions onto the event timetable at explicit start times (WRITE; internal UI endpoint). " +
        "Params: event_id, entries (array of {contribution_id, start_dt} — start_dt ISO-8601 with offset, e.g. 2026-09-23T14:00:00+02:00). " +
        "Use real DB contribution ids from indico_manage_contributions.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          event_id: { type: "integer", minimum: 0 },
          entries: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              additionalProperties: false,
              properties: {
                contribution_id: { type: "integer", minimum: 0 },
                start_dt: { type: "string", description: "ISO-8601 with tz offset" },
                session_block_id: { type: "integer", minimum: 0, description: "schedule into this session block instead of top level (required if the contribution belongs to a session)" },
              },
              required: ["contribution_id", "start_dt"],
            },
          },
        },
        required: ["event_id", "entries"],
      },
      async execute(_id, p) {
        const results = [];
        for (const e of p.entries) {
          const body = { contribution_id: e.contribution_id, start_dt: e.start_dt };
          if (e.session_block_id != null) body.session_block_id = e.session_block_id;
          const r = await indicoSend(`/event/${p.event_id}/manage/timetable/`, "POST", { json: body });
          results.push({ contribution_id: e.contribution_id, status: r.status, ok: r.ok && !(r.parsed && r.parsed.error) });
        }
        const done = results.filter((x) => x.ok).length;
        if (done === results.length) return okResult(JSON.stringify({ scheduled: true, results }), { status: 200 });
        return errResult("some schedules failed: " + JSON.stringify(results), { status: 207 });
      },
    });
  },
};
