# dmarc-service

Self-hosted, multi-tenant **DMARC / TLS-RPT report collector and viewer**.

Point your domains' `_dmarc` and `_smtp._tls` records at an address this
service controls, and it receives, parses, stores, and shows you the aggregate
reports that Google, Microsoft, Yahoo and everyone else send about mail
claiming to come from your domains - who is sending as you, what passes, what
fails, and from where.

Runs on a single VPS with Docker Compose, or on Kubernetes with the bundled
Helm chart. No SaaS, no per-domain pricing, your data stays yours.

**[See the feature tour with screenshots](docs/FEATURES.md)**

## Features

**Report intake**
- SMTP receiver (port 25) for aggregate and TLS-RPT report mail, plus an
  unauthenticated HTTPS `/tlsrpt` endpoint as required by RFC 8460.
- Parses DMARC aggregate XML and TLS-RPT JSON, plain, gzipped or zipped.
- Deliberate intake rules for report mail: accepts from anyone, no greylisting,
  50 MB default ceiling, duplicate reports ignored - see *Intake rules* below.
- **Direct or forward mode**: store locally, or run the same image as a
  stateless edge that relays messages over authenticated HTTPS to your main
  instance - for clouds that block inbound port 25 (DigitalOcean, for example).
- **Nothing silently lost**: mail for unknown or rotated-out addresses lands in
  an `unrouted` quarantine tenant instead of bouncing, and every message is
  kept verbatim.

**Control plane**
- Multi-tenant: tenants own domains; domains get unguessable, rotatable report
  addresses (bearer tokens, no `+` addressing). Single-tenant mode available.
- Tells you the **exact DNS records to publish** per domain, including the
  external-destination verification record (RFC 7489 section 7.1) when the monitored
  domain and the report host live in different organizational domains.
- **Live DNS verification**: every record is checked against the domain's
  *authoritative* nameservers - never a recursive resolver, whose cached
  positive and negative answers make a "live" check lie for hours after an
  edit. Statuses: published, missing, different-record-found, malformed
  (present but receivers would ignore it), lookup-failed. Cached 15 minutes,
  with a re-check button rate-limited to once a minute.
- **Address rotation**: mint a second address, publish it, then deactivate the
  old one - both accept mail during the overlap, so no report is lost.

**Manual import**
- Upload page (and `POST /upload`) for importing report files by hand: `.zip`,
  `.gz`, raw `.xml` / `.json`, or whole `.eml` messages, several at a time.
  Useful for historical archives, reports that landed in a mailbox, or data
  exported from another provider. Duplicates are detected, so re-importing the
  same archive is safe, and imports are attributed by the policy domain inside
  the file so they work for addresses that have since been rotated.

**Viewing**
- Dashboard with 30-day pass/fail/quarantine totals.
- **Graphs**: daily stacked pass/fail bars, 30 or 90 days, filterable per
  domain. Click any day to drill into that day's reports, then into a single
  report. Server-rendered SVG - no JS bundle - with a table fallback and
  color-blind-safe encoding (position + texture, not color alone).
- **Sending IP identification**: each source IP is resolved to the organisation
  that owns the network (via reverse DNS and RDAP, no API keys) and cached in
  the database, so a row reads "Twilio SendGrid" or "Microsoft" rather than a
  bare address. The reporter is not the sender: mail reported by Google may
  have been sent by anyone. Backfill older data with `dmarc-service enrich`.
- **Per-report detail**: every sending source with its IP, message count,
  DKIM/SPF results, disposition, and - the useful part - the domain the mail
  actually **authenticated as**, which separates your own misconfigured tools
  from outright spoofing.

**Accounts & API**
- The first account created in the UI becomes the **admin**; no bootstrap
  passwords in environment variables.
- The admin can configure **OIDC single sign-on** (Azure AD / Entra, Google
  Workspace, Keycloak, Okta, ...) in Settings; SSO users are auto-provisioned.
- Administrators can promote or demote other users in Settings; the last
  administrator cannot be demoted, so an installation always has one.
- Anyone, including SSO-provisioned users, can set a password as a fallback,
  and accounts without one are warned: a broken SSO configuration would
  otherwise lock them out. If it happens anyway, `dmarc-service set-password`
  and `dmarc-service disable-sso` recover an installation from the server.
- Every user can mint **personal API tokens** (hashed at rest, shown once) for
  `Authorization: Bearer` on `/api/*`; a static `API_TOKEN` is also supported
  for automation.
- Full JSON API with interactive docs at `/docs`.

## Architecture

```
                     MX example.com          +--------------------------+
  report senders  ------------------------>  | smtp (port 25)           |
  (google.com, ...)                          |  mode: direct  -> DB     |
                                             |  mode: forward -> HTTPS -+--> /api/ingest
                     https rua (TLS-RPT)     +--------------------------+
  senders/browsers ----------------------->  | web (port 8000)          |
                                             |  UI | API | /tlsrpt      |
                                             +------------+-------------+
                                                          |
                                                          v
                                                  PostgreSQL / SQLite
```

## Quickstart (local)

```sh
docker compose up --build
# UI on http://localhost:8000, SMTP on localhost:2525
```

Open the UI, create the first (admin) account, add a tenant and a domain - the
domain page then shows the DNS records to publish and verifies them live.

## Deployment

**Single VPS** - [`deploy/vps`](deploy/vps): compose file with PostgreSQL, web,
SMTP receiver and Caddy for automatic HTTPS certificates. Copy the directory,
fill in `.env`, `docker compose up -d`, point DNS at the host. Ports needed:
25, 80, 443.

**Kubernetes** - [`chart/dmarc-service`](chart/dmarc-service), built to adapt to
what you *don't* have:

| You don't have...            | Then...                                                                  |
|----------------------------|------------------------------------------------------------------------|
| an ingress controller      | `web.ingress.enabled=false` (default) - expose the Service yourself     |
| cert-manager               | leave `web.ingress.certManager.clusterIssuer` empty; bring TLS or none  |
| LoadBalancer support       | `smtp.service.type=NodePort` or `ClusterIP`                             |
| a cloud that allows port 25| `smtp.mode=forward` + a cheap external VPS running the same image       |
| PostgreSQL                 | `database.url=sqlite:////data/dmarc.db` + `persistence.enabled=true`    |
| a secrets operator         | inline values, or point at your own `existingSecret`                    |

### Intake rules (deliberate - do not "harden" these)

- **Accept mail from anyone.** Report mail authenticates as google.com,
  microsoft.com, etc. Filtering inbound reports by SPF/DMARC alignment against
  your own domains rejects your own data.
- **No greylisting.** Deferred report senders back off; some never retry.
- **50 MB ceiling.** Large senders produce large aggregate reports, and a size
  bounce is data you never get again.
- **Report addresses are bearer tokens.** Anyone who learns one can inject
  fake reports, so they are random and rotatable.
- **`/tlsrpt` is unauthenticated** (RFC 8460) and needs a publicly valid
  certificate. Reports about domains you have not registered are rejected.

## Configuration

Every setting is an environment variable (see `src/dmarc_service/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./dmarc.db` | SQLAlchemy URL (PostgreSQL recommended) |
| `REPORT_HOST` | `localhost` | Hostname report addresses live under |
| `EXTERNAL_URL` | `http://localhost:8000` | Public base URL (TLS-RPT records, SSO redirect) |
| `TENANCY_MODE` | `multi` | `multi` or `single` |
| `CONTROL_PLANE_ENABLED` | `true` | Disable to freeze tenant/domain provisioning |
| `API_TOKEN` | *(empty)* | Optional static bearer token for automation |
| `SESSION_SECRET` | *(empty)* | Cookie-signing key; set it to keep sessions across restarts |
| `INGEST_TOKEN` | *(empty)* | Enables `/api/ingest` for forward-mode edges |
| `SMTP_MODE` | `direct` | `direct` (store) or `forward` (relay) |
| `SMTP_FORWARD_URL` / `SMTP_FORWARD_TOKEN` | *(empty)* | Target for forward mode |
| `SMTP_TLS_CERT` / `SMTP_TLS_KEY` | *(empty)* | Offer STARTTLS when set |
| `SMTP_MAX_MESSAGE_BYTES` | `52428800` | Inbound message size ceiling |

## API

Interactive documentation at `/docs`. Main endpoints:

| Method & path | Purpose |
|---|---|
| `GET /healthz` | health check |
| `POST /tlsrpt` | TLS-RPT HTTPS endpoint (unauthenticated, per RFC) |
| `POST /api/ingest` | raw message intake for forward-mode edges |
| `GET/POST /api/tenants`, `DELETE /api/tenants/{slug}` | tenants |
| `POST /api/tenants/{slug}/domains`, `DELETE /api/domains/{name}` | domains |
| `GET /api/domains/{name}/dns?verify=true` | required records + live status |
| `POST/DELETE /api/domains/{name}/addresses[/{local_part}]` | address rotation |
| `GET /api/reports`, `/api/reports/{id}`, `/api/tls-reports`, `/api/summary` | data |

## Development

```sh
uv venv && uv pip install -e '.[dev]'
pytest          # unit + end-to-end SMTP, ingest, UI and DNS-check tests
ruff check .
```

Tagging `vX.Y.Z` runs the test suite, publishes the image and Helm chart to
GHCR, and (when `DEPLOY_SSH_KEY`/`DEPLOY_HOST` secrets exist) deploys to a VPS.

## License

[MIT](LICENSE)
