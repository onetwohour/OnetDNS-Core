# OnetDNS management API

The dashboard is built on this API and served from the same address, so anything you can do in the dashboard you can also script.

## Address

The API listens on `control_listen`, `127.0.0.1:8553` by default, and speaks plain HTTP/1.1. It answers only requests addressed to a loopback host. To manage a server from another machine, use an SSH tunnel, or an HTTPS reverse proxy on the same machine with `control_trusted_proxies` and `control_public_origins` set as the [README](README.md) describes.

Paths below are relative to that address, for example `http://127.0.0.1:8553/v1/stats`. The server also serves this reference as an OpenAPI 3.1 document at `/openapi.json`.

## Authentication

Send an API token in the `Authorization` header:

```sh
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8553/v1/stats
```

Tokens come from the config file (`control_token` and `control_admin_tokens` for admin access, `control_readonly_tokens` for read-only access) or from `POST /v1/tokens`, which shows a new token only once.

The dashboard signs in with `POST /v1/login` and uses the session cookie it gets back. A request authenticated by that cookie must send `X-OnetDNS-CSRF: 1` with every method other than GET, or it fails with 403. Requests with a bearer token do not need the header. If a request sends a bearer token, only the token counts: a wrong token fails even when the cookie is valid.

After repeated failed sign-ins for one user or from one address, sign-in is blocked for 15 minutes and `POST /v1/login` returns 429.

## Access

Every endpoint below lists who may call it:

| Access | Who may call it |
|---|---|
| none | Anyone, without a token or session |
| read-only | Any valid token or session |
| admin | Admin tokens and admin sessions |

A request without valid credentials gets 401, and a read-only caller gets 403 from an admin endpoint.

## Requests and responses

- Request bodies are JSON unless an endpoint lists another type. Send a matching `Content-Type`; a missing or different one gets 415. A body over 1 MiB gets 413.
- Responses are JSON unless an endpoint lists otherwise. Most endpoints reject a request with a 4xx status and `{"error":"..."}`. Authentication and access failures (401, 403) come back as plain text.
- While the server applies new settings, requests that change anything get 503. Retry once `/readyz` returns 200.
- Every request that changes something, and every authentication or access failure, goes to the audit log (`GET /v1/audit`).
- A change that rebuilds the filter answers after the rebuild, and a failed rebuild undoes it. Send `Prefer: respond-async` to get the answer once the change is saved; the filter catches up in the background, and `GET /v1/filter/apply` reports when it has. If that rebuild fails, the change stays saved and the previous filter keeps running. The header applies to `POST /v1/services`, `POST /v1/config/set`, `POST` and `DELETE /v1/rewrites`, `PATCH` and `DELETE /v1/filter/subscriptions`, `POST /v1/filter/subscriptions/refresh`, `POST` and `DELETE /v1/filter/rules`, and `POST`, `PATCH`, and `DELETE /v1/clients`. A `/v1/config/set` that changes `blocklists` or `allowlists` still waits, because only a rebuild can check those files.

## Jobs

Blocklist refreshes and the self-update check, install, and rollback run as background jobs. The request returns `{"id":...,"status":"running"}` at once. Poll `GET /v1/jobs/{id}` until `status` is `done` or `failed`; `result` then holds a one-line outcome.

## Clusters

With Raft enabled, requests that change settings are accepted only on the leader, which replicates them to every node. Followers reject them with 409. Self-update requests act only on the node you send them to. Nodes ignore cluster messages from nodes that run a different OnetDNS version, so update one node at a time.

## Example: update a node

```sh
API=http://127.0.0.1:8553
AUTH="Authorization: Bearer $ADMIN_TOKEN"

# Check for a newer release. The response carries a job id.
curl -s -X POST -H "$AUTH" $API/v1/system/update/check
curl -s -H "$AUTH" $API/v1/jobs/$JOB_ID

# What the check found: result is up_to_date, available, manual, or failed.
curl -s -H "$AUTH" $API/v1/system/update

# Install the version the check found. launch in the status above says how the node starts it.
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"version":"<new_version from the status>"}' $API/v1/system/update/apply
```

## Endpoints

<!-- Generated from openapi_json in crates/onetdns-control/src/api.rs; access comes from Role::allows. Do not edit between the markers. Regenerate with: ONETDNS_WRITE_API_DOC=1 cargo test -p onetdns-control api::reference -->
<!-- endpoints:begin -->

### Service

Liveness and readiness probes and this OpenAPI document. They need no authentication.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/healthz` | none | Process liveness check |
| GET | `/openapi.json` | none | This OpenAPI spec |
| GET | `/readyz` | none | DNS service readiness check |

#### `GET /healthz`

| Status | Response |
|---|---|
| 200 | ok |

#### `GET /openapi.json`

| Status | Response |
|---|---|
| 200 | OpenAPI 3.1 document |

#### `GET /readyz`

| Status | Response |
|---|---|
| 200 | ready |
| 503 | not ready |

### Authentication

Sign-in sessions, the first admin account, passwords, and API tokens.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/auth` | none | Current authentication state and role |
| POST | `/v1/setup` | none | Create the first admin account |
| POST | `/v1/login` | none | Sign in with username and password |
| POST | `/v1/logout` | none | End the current sign-in session |
| POST | `/v1/password` | read-only | Change the signed-in user's password and revoke all of that user's sessions |
| GET | `/v1/tokens` | read-only | Management API tokens. Token values are masked; only the role and a stable ID are returned |
| POST | `/v1/tokens` | admin | Issue a management API token (admin only). The token is read-only unless role is admin. The full token value is returned only once, in this response |
| DELETE | `/v1/tokens` | admin | Revoke a management API token (admin only). The primary control token from the config file cannot be deleted |

#### `GET /v1/auth`

The control token is for the API only and is never turned into a session cookie. Web console sessions are issued only by /v1/login.

| Status | Response |
|---|---|
| 200 | `{login_enabled,authenticated,role,user}` |

#### `POST /v1/setup`

Available only while no account exists. Returns 409 once any account exists.

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `user` | string | yes |
| `password` | string, at least 12 characters | yes |
| `code` | string | yes |

| Status | Response |
|---|---|
| 200 | Session cookie and {ok,user,role} |
| 400 | Username or password does not meet the rules |
| 409 | An account already exists |

#### `POST /v1/login`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `user` | string | yes |
| `password` | string | yes |

| Status | Response |
|---|---|
| 200 | Session cookie and {authenticated,role,user} |
| 401 | Credentials do not match |

#### `POST /v1/logout`

| Status | Response |
|---|---|
| 200 | `{ok:true}` |

#### `POST /v1/password`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `current_password` | string | yes |
| `new_password` | string, at least 12 characters | yes |

| Status | Response |
|---|---|
| 200 | `{changed,reloading}` |
| 403 | Current password does not match |

#### `GET /v1/tokens`

| Status | Response |
|---|---|
| 200 | `{tokens:[{id,role,masked}]}` |

#### `POST /v1/tokens`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `role` | string: `admin`, `readonly` | no |

| Status | Response |
|---|---|
| 200 | `{created,role,token,id}` |
| 400 | `{error}` |

#### `DELETE /v1/tokens`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `id` | string | yes |

| Status | Response |
|---|---|
| 200 | `{removed}` |
| 404 | `{error}` |

### Statistics and logs

Query statistics, recent queries, the dashboard stream, Prometheus metrics, and the audit log.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/stats` | read-only | Stats and recent DNS queries |
| GET | `/v1/metrics` | read-only | Dashboard stats |
| GET | `/v1/queries` | read-only | Recent DNS queries |
| GET | `/v1/stats/history/{range}` | read-only | Per-second time series of total and blocked queries |
| GET | `/v1/top` | read-only | Most queried domains, blocked entries, and clients |
| GET | `/v1/audit` | read-only | Management actions and access denials |
| GET | `/v1/dashboard/ws` | read-only | Dashboard WebSocket |
| GET | `/metrics` | read-only | Prometheus exposition |
| POST | `/v1/querylog/clear` | admin | Clear the recent query log |

#### `GET /v1/stats`

| Status | Response |
|---|---|
| 200 | Cumulative stats and recent queries |
| 401 | Not authenticated |

#### `GET /v1/metrics`

| Status | Response |
|---|---|
| 200 | `{metrics:{...}}` |

#### `GET /v1/queries`

| Status | Response |
|---|---|
| 200 | `{recent:[...]}` |

#### `GET /v1/stats/history/{range}`

| Parameter | In | Type |
|---|---|---|
| `range` | path | integer: `60`, `300`, `3600`, `86400`, `604800` |

| Status | Response |
|---|---|
| 200 | Time series points for the selected range |
| 400 | Unsupported range |

#### `GET /v1/top`

| Status | Response |
|---|---|
| 200 | Top entries by query count |

#### `GET /v1/audit`

| Status | Response |
|---|---|
| 200 | Recent management actions and access denials |

#### `GET /v1/dashboard/ws`

Sends query events, stats, top entries, and job status over one connection. Uses the onetdns.v1 subprotocol; pass resume.&lt;event_id&gt; to resume after reconnecting.

| Status | Response |
|---|---|
| 101 | WebSocket connection |

#### `GET /metrics`

| Status | Response |
|---|---|
| 200 | text/plain 0.0.4 |

#### `POST /v1/querylog/clear`

| Status | Response |
|---|---|
| 200 | `{cleared}` |

### Configuration

Read, validate, compare, and change the config file and the running config.

| Method | Path | Access | Summary |
|---|---|---|---|
| POST | `/v1/config/validate` | admin | Check whether a TOML fragment is valid when merged into the current config. The actual config is not changed |
| POST | `/v1/config/diff` | admin | Compare a TOML fragment with the current config file and show which entries change and how they are applied |
| POST | `/v1/config/apply` | admin | Apply a config fragment (admin only): changes only the given top-level entries and keeps the rest. Filters, access control, rate limits, the query log, and upstream DNS server addresses apply without interrupting service |
| POST | `/v1/config/rollback` | admin | Roll back to the state before the last config apply (admin only) |
| GET | `/v1/config/effective` | read-only | The config the server is actually running: defaults merged in, sensitive values masked. Direct edits to the config file are not included until applied |
| GET | `/v1/config` | read-only | Values saved in the config file, including changes not yet applied to the server. Returns error details when the file cannot be read or parsed |
| GET | `/v1/config/status` | read-only | Check whether the config file matches the running config and show entries not yet applied. service_restart lists the entries whose change restarts the DNS service when the file is applied; conditional_hot_reload_keys lists the settings that can restart it under the current configuration |
| POST | `/v1/config/reload` | admin | Validate config file changes and apply them to the running server (admin only) |
| POST | `/v1/config/set` | admin | Change settings (admin only): merges the values into the TOML file, validates, and saves. Hot-reloadable entries apply without dropping connections; others restart the DNS service. Nested entries use their dedicated APIs |
| POST | `/v1/config/set/diff` | admin | Show which entries a /v1/config/set request with this body would change and how they would be applied, without changing anything (admin only) |
| GET | `/v1/config/schema` | read-only | Settings that /v1/config/set can change, with their types and descriptions |

#### `POST /v1/config/validate`

Request body (`text/plain`): string.

| Status | Response |
|---|---|
| 200 | `{valid:true}` |
| 400 | `{valid:false,error}` |

#### `POST /v1/config/diff`

Request body (`text/plain`): string.

| Status | Response |
|---|---|
| 200 | `{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}` |
| 400 | Returns the error when the proposed config is invalid |

#### `POST /v1/config/apply`

Request body (`text/plain`): string.

| Status | Response |
|---|---|
| 200 | `{applied,mode,restart_required,reloading,changed}` |
| 400 | Returns the error when the input is invalid or the config file cannot be used |

#### `POST /v1/config/rollback`

| Status | Response |
|---|---|
| 200 | `{rolled_back,restart_required}` |
| 409 | Returns an error when there is no previous config |

#### `GET /v1/config/effective`

| Status | Response |
|---|---|
| 200 | Running config (JSON) |

#### `GET /v1/config`

| Status | Response |
|---|---|
| 200 | Saved config values or a file error (JSON) |

#### `GET /v1/config/status`

| Status | Response |
|---|---|
| 200 | `{in_sync,source,changed_keys[],service_restart[],restart_required,conditional_hot_reload_keys[],error?}` |

#### `POST /v1/config/reload`

| Status | Response |
|---|---|
| 200 | `{accepted,mode,restart_required,changed}` |
| 400 | {error}: config file is missing or invalid |

#### `POST /v1/config/set`

Request body (`application/json`): object.

| Status | Response |
|---|---|
| 200 | `{applied,mode,restart_required,reloading,changed,keys}` |
| 400 | {error}: unknown key or invalid value |

#### `POST /v1/config/set/diff`

Request body (`application/json`): object.

| Status | Response |
|---|---|
| 200 | `{added[],removed[],changed[],effective_changed[],hot_reload[],service_restart[],restart_required}` |
| 400 | {error}: unknown key or invalid value |

#### `GET /v1/config/schema`

| Status | Response |
|---|---|
| 200 | `{keys:[...],count}` |

### Filtering

Block and allow rules, blocklist subscriptions, blocked services, safe search, rewrites, access lists, and filter reports.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/backup` | read-only | Back up user filter data: block and allow rules, blocked services, refused domains, safe search |
| POST | `/v1/reload` | admin | Reload blocklists from the current settings |
| POST | `/v1/block` | admin | Add a blocked domain |
| POST | `/v1/allow` | admin | Add an allowed domain |
| POST | `/v1/restore` | admin | Restore a user filter data backup (replaces everything) |
| POST | `/v1/safesearch` | admin | Change the safe search setting |
| GET | `/v1/rewrites` | read-only | DNS rewrite rules |
| POST | `/v1/rewrites` | admin | Add or replace a DNS rewrite rule (admin only) |
| DELETE | `/v1/rewrites` | admin | Delete a DNS rewrite rule (admin only) |
| GET | `/v1/services` | read-only | Blockable services and whether each is blocked |
| POST | `/v1/services` | admin | Change service blocking |
| GET | `/v1/access` | read-only | Allowed, blocked, and silently dropped networks, what happens to clients that match no access rule (allow, deny, or drop), and domains answered with REFUSED. Use the config API to change them |
| GET | `/v1/plugins` | read-only | WASM plugin metrics |
| GET | `/v1/filter/report` | read-only | Filter rule load results and why rules were skipped |
| GET | `/v1/filter/top-rules` | read-only | Top N rules by hits (when track_rule_hits is enabled) |
| GET | `/v1/filter/sources` | read-only | Rule count and cumulative hits per block or allow list |
| GET | `/v1/filter/subscriptions` | read-only | Subscriptions with title, enabled state, and rule count. Built-in lists enabled by safe browsing and parental control are included with a preset value; they are turned on and off only by those settings and cannot be deleted or disabled here |
| POST | `/v1/filter/subscriptions` | admin | Add a blocklist subscription (admin only). The list is downloaded first and is not saved if the download fails. With background, the download and save run as a job; follow it at /v1/jobs/{id} |
| PATCH | `/v1/filter/subscriptions` | admin | Enable or disable a blocklist subscription (admin only) |
| DELETE | `/v1/filter/subscriptions` | admin | Delete a blocklist subscription (admin only) |
| POST | `/v1/filter/subscriptions/refresh` | admin | Refresh the given blocklist subscription (admin only). With `Prefer: respond-async`, the download runs as a job |
| GET | `/v1/filter/apply` | read-only | Whether changes saved with Prefer: respond-async have reached the running filter |
| GET | `/v1/filter/rules` | read-only | User block and allow rules, and domains answered with REFUSED |
| POST | `/v1/filter/rules` | admin | Add a filter rule (admin only) |
| DELETE | `/v1/filter/rules` | admin | Delete a filter rule (admin only) |

#### `GET /v1/backup`

| Status | Response |
|---|---|
| 200 | `{version,block,allow,services,refused_domains,safe_search}` |

#### `POST /v1/reload`

| Status | Response |
|---|---|
| 200 | `{block,allow}` |
| 403 | This action requires the admin role |

#### `POST /v1/block`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `domain` | string | yes |

| Status | Response |
|---|---|
| 200 | `{block,allow}` |

#### `POST /v1/allow`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `domain` | string | yes |

| Status | Response |
|---|---|
| 200 | `{block,allow}` |

#### `POST /v1/restore`

Request body (`application/json`): object.

| Status | Response |
|---|---|
| 200 | `{block,allow}` |
| 400 | Invalid input |

#### `POST /v1/safesearch`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `enable` | boolean | yes |

| Status | Response |
|---|---|
| 200 | `{safe_search}` |
| 400 | Could not save the config file |

#### `GET /v1/rewrites`

| Status | Response |
|---|---|
| 200 | `{rewrites:[{domain,answer}]}` |

#### `POST /v1/rewrites`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `domain` | string | yes |
| `answer` | string | yes |

| Status | Response |
|---|---|
| 200 | `{added,domain}` |
| 400 | `{error}` |

#### `DELETE /v1/rewrites`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `domain` | string | yes |

| Status | Response |
|---|---|
| 200 | `{removed,domain}` |
| 404 | `{error}` |

#### `GET /v1/services`

| Status | Response |
|---|---|
| 200 | `{count,services:[{id,name,blocked}]}` |

#### `POST /v1/services`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `service` | string | yes |
| `enable` | boolean | yes |

| Status | Response |
|---|---|
| 200 | `{block,allow}` |

#### `GET /v1/access`

| Status | Response |
|---|---|
| 200 | `{allowed,blocked,dropped,unlisted,refused_domains}` |

#### `GET /v1/plugins`

| Status | Response |
|---|---|
| 200 | `[{name,eval,error,block,latency_us}]` |

#### `GET /v1/filter/report`

| Status | Response |
|---|---|
| 200 | `{rules_total,rules_applied,rules_skipped,skip_reasons}` |

#### `GET /v1/filter/top-rules`

| Status | Response |
|---|---|
| 200 | `{enabled,top:[{rule,hits}]}` |

#### `GET /v1/filter/sources`

| Status | Response |
|---|---|
| 200 | `{hits_enabled,sources:[{source,rules,hits}]}` |

#### `GET /v1/filter/subscriptions`

| Status | Response |
|---|---|
| 200 | {lists:[{url,title,enabled,rules,updated_unix,preset?}],count,block_domains}. preset is safe_browsing or parental_control |

#### `POST /v1/filter/subscriptions`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `url` | string | yes |
| `title` | string | no |
| `enabled` | boolean | no |
| `background` | boolean | no |

| Status | Response |
|---|---|
| 200 | {added}, or {id,status} with background |
| 400 | `{error}` |
| 409 | {error}: this node is not the cluster leader |
| 503 | `{error}` |

#### `PATCH /v1/filter/subscriptions`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `url` | string | yes |
| `enabled` | boolean | yes |

| Status | Response |
|---|---|
| 200 | `{updated}` |
| 400 | `{error}` |

#### `DELETE /v1/filter/subscriptions`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `url` | string | yes |

| Status | Response |
|---|---|
| 200 | `{removed,subscriptions,block}` |
| 404 | `{error}` |

#### `POST /v1/filter/subscriptions/refresh`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `url` | string | yes |

| Status | Response |
|---|---|
| 200 | {refreshed:true}, or {id,status} with Prefer: respond-async |
| 400 | `{error}` |

#### `GET /v1/filter/apply`

| Status | Response |
|---|---|
| 200 | `{pending,error}` |

#### `GET /v1/filter/rules`

| Status | Response |
|---|---|
| 200 | `{block,allow,refused_domains}` |

#### `POST /v1/filter/rules`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `kind` | string: `block`, `allow`, `refused_domain` | yes |
| `rule` | string | yes |

| Status | Response |
|---|---|
| 200 | `{updated:true}` |

#### `DELETE /v1/filter/rules`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `kind` | string: `block`, `allow`, `refused_domain` | yes |
| `rule` | string | yes |

| Status | Response |
|---|---|
| 200 | `{updated:true}` |

### Clients

Per-client policies.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/clients` | read-only | Per-client policies |
| POST | `/v1/clients` | admin | Add a client policy (admin only): ordinary block and allow policies apply without dropping connections; a dedicated upstream DNS server or a new MAC match restarts the DNS service |
| PATCH | `/v1/clients` | admin | Turn filtering on or off for a client (admin only) |
| DELETE | `/v1/clients` | admin | Delete a client policy (admin only) |

#### `GET /v1/clients`

| Status | Response |
|---|---|
| 200 | `[{name,nets,client_ids,tags,block_rules,disable_filtering}]` |

#### `POST /v1/clients`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |
| `ids` | array of strings | no |
| `client_ids` | array of strings | no |
| `mac` | array of strings | no |
| `tags` | array of strings | no |
| `block` | array of strings | no |
| `allow` | array of strings | no |
| `blocked_services` | array of strings | no |
| `disable_filtering` | boolean | no |
| `safe_search` | boolean | no |

| Status | Response |
|---|---|
| 200 | `{added,reloading}` |
| 400 | `{error}` |

#### `PATCH /v1/clients`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |
| `disable_filtering` | boolean | yes |

| Status | Response |
|---|---|
| 200 | `{updated,disable_filtering,reloading}` |

#### `DELETE /v1/clients`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |

| Status | Response |
|---|---|
| 200 | `{removed,reloading}` |
| 400 | `{error}` |

### Resolution

Listen addresses, upstream DNS servers, the response cache, and query diagnostics.

| Method | Path | Access | Summary |
|---|---|---|---|
| POST | `/v1/policies/simulate` | read-only | Preview the policy and filter result for a DNS query |
| POST | `/v1/explain` | read-only | Preview the decision for a DNS query: explains the policy, filter, response code, and handling without sending a real query or changing the cache |
| GET | `/v1/listeners` | read-only | Active DNS listen addresses and per-transport status |
| POST | `/v1/resolve` | read-only | Send one real query to this server |
| POST | `/v1/upstreams/test` | admin | Test an upstream DNS server (admin only): sends a test query and reports reachability, latency, and response code |
| POST | `/v1/cache/flush` | admin | Flush the whole response cache (admin only). Returns the number of entries removed |
| GET | `/v1/upstreams` | read-only | Upstream DNS servers |
| POST | `/v1/upstreams` | admin | Add an upstream DNS server (admin only; applies without dropping connections) |
| DELETE | `/v1/upstreams` | admin | Delete an upstream DNS server (admin only; applies without dropping connections) |

#### `POST /v1/policies/simulate`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `client` | string | no |
| `qname` | string | yes |
| `qtype` | string | no |

| Status | Response |
|---|---|
| 200 | `{policy,filter,filter_stage,filter_matched,filter_list,decision}` |

#### `POST /v1/explain`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `client` | string | no |
| `client_id` | string | no |
| `qname` | string | yes |
| `qtype` | string | no |

| Status | Response |
|---|---|
| 200 | `{decision,rcode,policy,filter,filter_stage,filter_matched,filter_list,matched,client_safe_search,backend,dnssec,resolution}` |

#### `GET /v1/listeners`

| Status | Response |
|---|---|
| 200 | `{listeners:[...]}` |

#### `POST /v1/resolve`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `qname` | string | yes |
| `qtype` | string | no |

| Status | Response |
|---|---|
| 200 | `{rcode,elapsed_ms,server,answers[]}` |
| 400 | Could not send the query |

#### `POST /v1/upstreams/test`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `addr` | string | yes |

| Status | Response |
|---|---|
| 200 | `{ok,latency_ms,rcode,addr}` |
| 400 | `{error}` |

#### `POST /v1/cache/flush`

| Status | Response |
|---|---|
| 200 | `{flushed}` |

#### `GET /v1/upstreams`

| Status | Response |
|---|---|
| 200 | `[{id,addr,queries?,ok?,fail?,ewma_ms?}]` |

#### `POST /v1/upstreams`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `addr` | string | yes |

Other fields are rejected.

| Status | Response |
|---|---|
| 200 | `{added,mode,restart_required}` |
| 400 | `{error}` |

#### `DELETE /v1/upstreams`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `addr` | string | yes |

Other fields are rejected.

| Status | Response |
|---|---|
| 200 | `{removed,mode,restart_required}` |
| 400 | `{error}` |

### TLS

Certificates for encrypted DNS: status, validation, replacement, revocation checks, and ACME issuance.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/tls` | read-only | TLS certificate and private key paths, and encrypted DNS listener status |
| POST | `/v1/tls/validate` | admin | Validate the configured certificate, private key, chain, and validity period (admin only). Trust path and hostname are not checked |
| POST | `/v1/tls/configure` | admin | Replace the TLS certificate and private key (admin only): accepts PEM bodies or file paths, checks the format and that the key matches, saves them, and restarts the encrypted DNS listeners |
| POST | `/v1/tls/revocation-check` | admin | Check OCSP and CRL revocation status of a certificate chain (admin only). Fetches from the URLs in the certificate and verifies signatures |
| POST | `/v1/acme/issue` | admin | Issue an ACME certificate or register an account (admin only). Answers HTTP-01 and DNS-01 challenges automatically and saves the issued certificate and private key to the configured files |

#### `GET /v1/tls`

| Status | Response |
|---|---|
| 200 | `{configured,cert,key,doh_listeners,dot_listeners}` |

#### `POST /v1/tls/validate`

| Status | Response |
|---|---|
| 200 | `{material_valid,valid:false,trusted:false,hostname_checked:false,chain_len}` |
| 400 | `{error}` |

#### `POST /v1/tls/configure`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `certificate_chain` | string | no |
| `private_key` | string | no |
| `cert_path` | string | no |
| `key_path` | string | no |

Other fields are rejected.

| Status | Response |
|---|---|
| 200 | `{configured,chain_len,reloading,cert,key}` |
| 400 | `{error}` |

#### `POST /v1/tls/revocation-check`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `certificate_chain` | string | yes |

| Status | Response |
|---|---|
| 200 | `{ocsp,crl,ocsp_urls,crl_urls,revoked}` |
| 400 | `{error}` |

#### `POST /v1/acme/issue`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `directory` | string | no |
| `domains` | array | no |
| `contact` | string | no |
| `challenge` | string | no |
| `account_only` | boolean | no |

| Status | Response |
|---|---|
| 200 | `{account,issued,cert_file,key_file}` |
| 400 | `{error}` |

### Zones

Authoritative zones, their records, and their DNSSEC status.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/zones` | read-only | Authoritative zones |
| GET | `/v1/zones/{origin}` | read-only | Authoritative zone with structured records |
| PUT | `/v1/zones/{origin}` | admin | Create or replace an authoritative DNS zone (admin only; body is an RFC 1035 zone file) |
| DELETE | `/v1/zones/{origin}` | admin | Delete an authoritative DNS zone (admin only) |
| GET | `/v1/zones/{origin}/dnssec` | read-only | Zone DNSSEC status (signed, DNSKEYs, DS for the parent) |
| POST | `/v1/zones/{origin}/records` | admin | Add a DNS record (admin only): saves, re-signs with DNSSEC, and sends NOTIFY |
| DELETE | `/v1/zones/{origin}/records` | admin | Delete DNS records (admin only): with value, deletes only records whose value also matches |

#### `GET /v1/zones`

| Status | Response |
|---|---|
| 200 | `[{origin,serial,records}]` |

#### `GET /v1/zones/{origin}`

| Status | Response |
|---|---|
| 200 | `{origin,serial,record_count,records:[{name,type,ttl,value}]}` |
| 404 | `{error}` |

#### `PUT /v1/zones/{origin}`

Request body (`text/plain`): string.

| Status | Response |
|---|---|
| 200 | `{origin,serial,records,persisted}` |
| 400 | {error}: invalid DNS zone data |
| 403 | This action requires the admin role |

#### `DELETE /v1/zones/{origin}`

| Status | Response |
|---|---|
| 200 | `{deleted}` |
| 404 | `{error}` |

#### `GET /v1/zones/{origin}/dnssec`

| Status | Response |
|---|---|
| 200 | `{signed,dnskeys:[{key_tag,flags,algorithm,role}],ds:{key_tag,algorithm,digest_type,digest}}` |

#### `POST /v1/zones/{origin}/records`

Request body (`text/plain`): string.

| Status | Response |
|---|---|
| 200 | `{origin,serial,records,persisted,signed}` |
| 400 | {error}: invalid DNS record |

#### `DELETE /v1/zones/{origin}/records`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |
| `type` | string | yes |
| `value` | string | no |

| Status | Response |
|---|---|
| 200 | `{deleted,origin,serial,persisted}` |
| 404 | {error}: no matching entry |

### DHCP

DHCP leases and static assignments.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/dhcp/leases` | read-only | Active DHCP leases. IPv4 entries include the binding identity, last MAC, and the vendor and hostname when known |
| POST | `/v1/dhcp/leases` | admin | Apply DHCP leases sent by the peer node in a high-availability setup (admin only). Accepts one object or a snapshot array with identity and last MAC; rejects the whole request if any entry is malformed |
| GET | `/v1/dhcp/static` | read-only | DHCP static assignments (fixed IP per mac:&lt;hex&gt; or id:&lt;hex&gt; identity) |
| POST | `/v1/dhcp/static` | admin | Add or change a DHCP static assignment (admin only). Applies to the pool immediately and saves to file |
| DELETE | `/v1/dhcp/static` | admin | Delete a DHCP static assignment (admin only) |

#### `GET /v1/dhcp/leases`

| Status | Response |
|---|---|
| 200 | `{v4:[{ip,identity,mac,vendor,hostname,expires,remaining}],v6:[{ip,duid,expires,remaining}]}` |

#### `POST /v1/dhcp/leases`

Request body (`application/json`): object or array of objects.

Example:

```json
[{"identity":"id:0102","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.100","expiry":"1900000000","hostname":"host1"}]
```

| Status | Response |
|---|---|
| 200 | `{synced}` |
| 400 | `{error}` |

#### `GET /v1/dhcp/static`

| Status | Response |
|---|---|
| 200 | {available,reservations:[{identity,ip,hostname}]}. available is false when no DHCPv4 pool is running; adds and deletes are then rejected |

#### `POST /v1/dhcp/static`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `identity` | string | yes |
| `ip` | string | yes |
| `hostname` | string | no |

| Status | Response |
|---|---|
| 200 | `{added,identity,ip}` |
| 400 | `{error}` |

#### `DELETE /v1/dhcp/static`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `identity` | string | yes |

| Status | Response |
|---|---|
| 200 | `{removed,identity}` |
| 404 | `{error}` |

### Cluster

Cluster node status and Raft config proposals.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/cluster/nodes` | read-only | Cluster node status. With consensus enabled, includes role, term, leader, and apply position |
| POST | `/v1/cluster/propose` | admin | Propose a config change to the Raft leader (admin only): replicates {patch:{key:value}} to every node and applies it. A null value removes the entry. Node-local settings are rejected. With Raft enabled, other config-changing management requests are also accepted only on the leader and replicated the same way; followers reject them with 409 |

#### `GET /v1/cluster/nodes`

| Status | Response |
|---|---|
| 200 | {self:{id,role,backend,listeners,leader,term,commit_index,last_applied,last_index,snapshot_index,retained_log_entries,fatal,healthy,version},peers:[{id,url,healthy,role,rtt_ms,version}],identity:{node_id,public_key,peer_entry}}. identity.public_key is derived from the configured Raft signing key, and peer_entry is the entry to add as-is to cluster_raft_peers on other nodes. Both are null without a signing key. self.version is this node's OnetDNS version. peers[].version is the version in the last authenticated cluster message from that node, null until one arrives. Nodes ignore cluster messages from nodes that run a different version |

#### `POST /v1/cluster/propose`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `patch` | object | yes |

Other fields are rejected.

| Status | Response |
|---|---|
| 200 | `{committed,applied,index}` |
| 400 | `{error}` |

### Jobs

Background jobs. Requests that take long return a job ID to poll here.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/jobs` | read-only | Background jobs |
| POST | `/v1/jobs/refresh` | admin | Start a blocklist refresh job (admin only) |
| GET | `/v1/jobs/{id}` | read-only | Status of one job (polling) |

#### `GET /v1/jobs`

| Status | Response |
|---|---|
| 200 | `[{id,kind,status,created,finished,result}]` |

#### `POST /v1/jobs/refresh`

| Status | Response |
|---|---|
| 200 | `{id,status}` |

#### `GET /v1/jobs/{id}`

| Status | Response |
|---|---|
| 200 | `{id,kind,status,...}` |
| 404 | `{error}` |

### System

Changes to the host this server runs on: network adapters, firewall rules, the boot service, and the OS DNS client.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/system/network-adapters` | read-only | List host network adapters |
| POST | `/v1/system/firewall` | admin | Open a port in the host firewall for UDP, TCP, or both, or remove the rule for that port (admin only) |
| GET | `/v1/system/service` | read-only | Boot service registration status |
| POST | `/v1/system/service` | admin | Install or remove the boot service (admin only) |
| POST | `/v1/system/dns-client` | admin | Change the OS DNS client settings (admin only) |
| POST | `/v1/system/dns-client/restore` | admin | Restore the OS DNS client settings (admin only) |

#### `GET /v1/system/network-adapters`

| Status | Response |
|---|---|
| 200 | Adapter JSON |
| 400 | Could not retrieve the information |

#### `POST /v1/system/firewall`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `port` | integer | yes |
| `udp` | boolean | no |
| `tcp` | boolean | no |
| `action` | string: `allow`, `remove` | no |

| Status | Response |
|---|---|
| 200 | Result |
| 400 | Could not apply the change |

#### `GET /v1/system/service`

| Status | Response |
|---|---|
| 200 | `{supported,installed,running}` |

#### `POST /v1/system/service`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `action` | string: `install`, `uninstall` | yes |

| Status | Response |
|---|---|
| 200 | Result |
| 400 | Could not apply |

#### `POST /v1/system/dns-client`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `adapter` | string | yes |
| `servers` | array of strings | yes |

| Status | Response |
|---|---|
| 200 | Result |
| 400 | Could not apply the change |

#### `POST /v1/system/dns-client/restore`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `adapter` | string | yes |

| Status | Response |
|---|---|
| 200 | Restore result |
| 400 | Could not restore |

### Updates

Self-update of this node: release checks, installation, and rollback.

| Method | Path | Access | Summary |
|---|---|---|---|
| GET | `/v1/system/update` | read-only | Self-update status of this node: its version, whether this build updates itself and why not, how a new version is started, the last release check, the update record, and the version a rollback would reinstall |
| POST | `/v1/system/update/check` | admin | Start a job that checks GitHub for a newer release (admin only) |
| POST | `/v1/system/update/apply` | admin | Start a job that installs the release found by the last check and starts it (admin only). version must be the version the last check found |
| POST | `/v1/system/update/rollback` | admin | Start a job that reinstalls the version replaced by the last committed update and starts it (admin only) |

#### `GET /v1/system/update`

| Status | Response |
|---|---|
| 200 | `{version,target,participating,reason,launch,release_check,task,checked_at,result,new_version,release_url,detail,record,rollback}` |

#### `POST /v1/system/update/check`

| Status | Response |
|---|---|
| 200 | `{id,status}` |
| 409 | `{error}` |

#### `POST /v1/system/update/apply`

Request body (`application/json`):

| Field | Type | Required |
|---|---|---|
| `version` | string | yes |

| Status | Response |
|---|---|
| 200 | `{id,status}` |
| 400 | `{error}` |
| 409 | `{error}` |

#### `POST /v1/system/update/rollback`

| Status | Response |
|---|---|
| 200 | `{id,status}` |
| 409 | `{error}` |

<!-- endpoints:end -->
