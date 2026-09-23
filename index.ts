import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const TOKEN_PATH = join(homedir(), "openclaw", "indicotoken");
const BASE = "https://indico.cern.ch";
const UA = "openclaw-indico-plugin/0.1";

function getToken() {
  return readFileSync(TOKEN_PATH, "utf8").trim();
}

async function indicoGet(pathWithQuery) {
  const res = await fetch(BASE + pathWithQuery, {
    headers: { Authorization: "Bearer " + getToken(), "User-Agent": UA },
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (_) { /* not JSON (HTML error page) */ }
  return { status: res.status, ok: res.ok, parsed, text };
}

const NoParams = Type.Object({});

const toolRenderers = {
  user: (r) => JSON.stringify(r.parsed ?? r.text.slice(0, 500), null, 2),
  generic: (r) => {
    if (r.parsed == null) return r.text.slice(0, 2000);
    return JSON.stringify(r.parsed, null, 2).slice(0, 6000);
  },
};

function makeTool(name, description, params, buildPath) {
  return {
    name,
    description,
    parameters: params,
    async execute(_id, p) {
      const r = await indicoGet(buildPath(p || {}));
      if (!r.ok) {
        return {
          content: [{ type: "text", text: `Indico HTTP ${r.status}: ${r.text.slice(0, 300)}` }],
          details: { ok: false, status: r.status },
        };
      }
      const rendered = toolRenderers.generic(r);
      return { content: [{ type: "text", text: rendered }], details: { ok: true, status: r.status } };
    },
  };
}

function esc(s) { return encodeURIComponent(String(s)); }

export default definePluginEntry({
  id: "indico",
  name: "Indico (CERN)",
  description: "Indico HTTP export API tools for indico.cern.ch.",
  register(api) {
    api.registerTool(makeTool(
      "indico_user",
      "Whoami for the Indico API token — returns the owning account profile.",
      NoParams,
      () => "/api/user/",
    ));
    api.registerTool(makeTool(
      "indico_search_events",
      "Search Indico events. Params: q (query text; optional), from/to (YYYY-MM-DD), limit (int, max 100).",
      Type.Object({
        q: Type.Optional(Type.String({ description: "free text query" })),
        from: Type.Optional(Type.String({ pattern: "^\\d{4}-\\d{2}-\\d{2}$" })),
        to: Type.Optional(Type.String({ pattern: "^\\d{4}-\\d{2}-\\d{2}$" })),
        limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
      }),
      (p) => {
        const parts = ["occ=yes", `limit=${p.limit ?? 25}`];
        if (p.q) parts.push(`q=${esc(p.q)}`);
        if (p.from) parts.push(`from=${esc(p.from)}`);
        if (p.to) parts.push(`to=${esc(p.to)}`);
        return "/export/event/search.json?" + parts.join("&");
      },
    ));
    api.registerTool(makeTool(
      "indico_category_events",
      "List events in an Indico category. Params: category_id (int), from/to (YYYY-MM-DD), limit.",
      Type.Object({
        category_id: Type.Integer({ minimum: 0, description: "Indico category id, e.g. 2" }),
        from: Type.Optional(Type.String({ pattern: "^\\d{4}-\\d{2}-\\d{2}$" })),
        to: Type.Optional(Type.String({ pattern: "^\\d{4}-\\d{2}-\\d{2}$" })),
        limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
      }),
      (p) => {
        const parts = [`limit=${p.limit ?? 25}`, "occ=yes"];
        if (p.from) parts.push(`from=${esc(p.from)}`);
        if (p.to) parts.push(`to=${esc(p.to)}`);
        return `/export/categ/${p.category_id}.json?` + parts.join("&");
      },
    ));
    api.registerTool(makeTool(
      "indico_event_details",
      "Get detailed info about one Indico event. Params: event_id (int).",
      Type.Object({ event_id: Type.Integer({ minimum: 0, description: "Indico event id" }) }),
      (p) => `/export/event/${p.event_id}.json?occ=yes`,
    ));
  },
});
