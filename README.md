# openclaw-indico

OpenClaw plugin exposing [Indico](https://indico.cern.ch) (CERN's event management system) as agent tools.

The tools cover both the documented classic HTTP API (`/export/*`, `/api/user/`) and Indico's *internal* management endpoints that the public documentation does not enumerate. The internal write paths were reverse-engineered from the Angular client calls that the Indico UI itself makes.

## Auth

One Indico personal access token (`indp_...`) is used for everything. Set it for the gateway via `indico-token` credential. The same Bearer header satisfies the classic export API, the oauth-scoped `/api/*` endpoints, and every internal management endpoint — no SSO browser flow, no Kerberos.

For ACL writes, Indico requires **signed** user identifiers (e.g. `User:49024:NDkwMjQ.<sig>`); unsigned `User:<id>` entries are silently dropped by the protection widgets. Signatures are minted via the scoped user-search flow: `GET /user/search/token?event_id=N` followed by `GET /user/search/?token=...&email={exact}&exact=1`. The plugin handles this for you when you grant by email.

## Tools

### Read / export (classic API)

| Tool | Endpoint |
|---|---|
| `indico_user` | `GET /api/user/` |
| `indico_user_details` | `GET /export/user/{id}.json` |
| `indico_search_events` | `GET /export/event/search/{q}.json` |
| `indico_category_events` | `GET /export/categ/{id}.json` |
| `indico_event_details` | `GET /export/event/{id}.json` |
| `indico_timetable` | `GET /export/timetable/{id}.json` |
| `indico_download_file` | material/file download |
| `indico_room_by_name`, `indico_room_details`, `indico_reservations` | `/export/room*.json`, `/export/reservation/` |

### Write / management (internal endpoints)

| Tool | Purpose |
|---|---|
| `indico_create_event` / `indico_delete_event` | create event in a category; hard-delete |
| `indico_create_session` / `indico_edit_session` / `indico_delete_session` | session CRUD |
| `indico_create_session_block` | empty timetable block/slot for a session |
| `indico_create_contribution` / `indico_edit_contribution` / `indico_delete_contribution` | contribution CRUD |
| `indico_manage_contributions` | list contributions with real DB ids |
| `indico_assign_contribution` | link/unlink contribution ↔ session |
| `indico_schedule_contributions` | place contribution (or block) at an explicit start time, optionally inside a session block |
| `indico_unschedule_contribution` | drop a contribution from the timetable without deleting it |
| `indico_edit_timetable_entry` | patch an existing timetable entry |
| `indico_get_protection` / `indico_search_users` / `indico_set_protection` | snapshot/set ACLs at event, session-block, or contribution scope |
| `indico_book_room` | room booking via legacy API |

## Endpoint notes (reverse-engineering recap)

- All write endpoints are POST/GET under `<ev>/manage/...` (the Angular management UI's XHR calls). JSON payload format works.
- **Session blocks must exist before contributions can be scheduled into a session.** `indico_create_session_block` handles this.
- Searching Indico users from a manager context requires the scoped search token fetched per-event (see Auth). `indico_search_users` does this transparently. The result items include the signed identifier you can feed straight into `indico_set_protection`.
- Protection/ACL writes require signed identifiers (see Auth). The tools re-mint them on the fly when given plain ids/emails.
- Endpoints are coupled to the Indico server version; verified against indico.cern.ch running Indico 3.3.

## Layout

- `index.ts` — source
- `index.js` — compiled artifact the gateway loads
- `openclaw.plugin.json` — manifest (contracts + tool list)
- `package.json` / `package-lock.json` — npm metadata

## License

MIT — see `LICENSE`.
