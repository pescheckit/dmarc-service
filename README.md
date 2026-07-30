# dmarc-service

Self-hosted, multi-tenant **DMARC / TLS-RPT report collector and viewer**.

Point your domains' `_dmarc` and `_smtp._tls` DNS records at an address this
service controls, and it receives, parses, stores, and displays the aggregate
reports that Google, Microsoft, Yahoo, and everyone else send about mail
claiming to come from your domains.

## Why this exists

Hosted DMARC dashboards are convenient until you have many domains, many
clients, or data-locality requirements. dmarc-service is a small,
self-contained alternative:

- **One image, three roles** — `web` (API + UI + TLS-RPT HTTPS endpoint),
  `smtp` (report intake MTA), `migrate` (schema).
- **Multi-tenant** — run it for yourself or for all of your clients. Each
  tenant gets domains; each domain gets unguessable, rotatable report
  addresses minted by the control plane.
- **DNS told to you, not guessed by you** — for every domain the API returns
  the exact records to publish, including the external-destination
  verification records (RFC 7489 §7.1) when the monitored domain and report
  host live in different organizational domains.
- **Nothing silently lost** — unknown recipients, typo'd records, and
  mid-rotation stragglers land in an `unrouted` quarantine tenant instead of
  being bounced.

## Architecture

```
                    MX example.com            ┌──────────────────────────┐
report senders  ──────────────────────────▶   │ smtp (port 25)           │
(google.com, ...)                             │  mode: direct ──▶ DB     │
                                              │  mode: forward ─▶ HTTPS ─┼──▶ /api/ingest
                    https rua (TLS-RPT)       ├──────────────────────────┤
senders/browsers ─────────────────────────▶   │ web (port 8000)          │
                                              │  UI · API · /tlsrpt      │
                                              └────────────┬─────────────┘
                                                           ▼
                                                       PostgreSQL
```

The **forward mode** matters when your main cluster's cloud blocks inbound
port 25 (DigitalOcean, for example): run the same image as a tiny stateless
"edge" on any VPS that allows SMTP, and it relays every message over
authenticated HTTPS to your main deployment. No database or secrets on the
edge beyond one token.

## Quickstart (local)

```sh
docker compose up --build
# UI on http://localhost:8000, SMTP on localhost:2525

# create a tenant and a domain; the response contains the DNS records to publish
curl -X POST localhost:8000/api/tenants -H 'content-type: application/json' \
     -d '{"slug": "acme", "name": "Acme Inc"}'
curl -X POST localhost:8000/api/tenants/acme/domains -H 'content-type: application/json' \
     -d '{"name": "example.com"}'
```

## Deployment

A Helm chart lives in [`chart/dmarc-service`](chart/dmarc-service). It is
built to adapt to what you *don't* have:

| You don't have…            | Then…                                                                 |
|----------------------------|-----------------------------------------------------------------------|
| an ingress controller      | `web.ingress.enabled=false` (default) — expose the Service yourself   |
| cert-manager               | leave `web.ingress.certManager.clusterIssuer` empty, bring TLS or none |
| LoadBalancer support       | `smtp.service.type=NodePort` or `ClusterIP`                            |
| a cloud that allows port 25| `smtp.mode=forward` + a cheap external VPS running the same chart/image |
| PostgreSQL                 | `database.url=sqlite:////data/dmarc.db` + `persistence.enabled=true` (single replica, small installs) |
| a secrets operator         | put the DB URL/tokens straight into values, or reference an `existingSecret` |

See [`chart/dmarc-service/values.yaml`](chart/dmarc-service/values.yaml) for
the full surface.

### Intake rules (important, and deliberate)

- Accept mail from **anyone** — report mail authenticates as google.com,
  microsoft.com, etc. Never filter inbound reports by SPF/DMARC alignment
  against your own domains: you would reject your own data.
- **No greylisting** — deferred report senders back off; some stop retrying.
- **50 MB default size limit** — big senders produce big aggregate reports,
  and a size bounce is data you don't get again.
- Report addresses are **bearer tokens**: anyone who learns one can inject
  fake reports. They are random, rotatable (two active addresses per domain
  during rollover), and have no `+` addressing.
- The TLS-RPT HTTPS endpoint (`POST /tlsrpt`) is unauthenticated by design
  (RFC 8460) and must be reachable with a publicly valid certificate.

## Configuration

Everything is an environment variable (see `src/dmarc_service/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./dmarc.db` | SQLAlchemy URL (PostgreSQL recommended) |
| `REPORT_HOST` | `localhost` | Hostname report addresses live under |
| `EXTERNAL_URL` | `http://localhost:8000` | Public base URL (used in TLS-RPT records) |
| `TENANCY_MODE` | `multi` | `multi` or `single` |
| `CONTROL_PLANE_ENABLED` | `true` | Disable to freeze tenant/domain provisioning |
| `API_TOKEN` | *(empty)* | If set, required as `Bearer` on `/api/*` |
| `INGEST_TOKEN` | *(empty)* | Enables `/api/ingest` for forward-mode edges |
| `SMTP_MODE` | `direct` | `direct` (store) or `forward` (relay to `/api/ingest`) |
| `SMTP_FORWARD_URL` / `SMTP_FORWARD_TOKEN` | *(empty)* | Target for forward mode |
| `SMTP_TLS_CERT` / `SMTP_TLS_KEY` | *(empty)* | Offer STARTTLS when set |
| `SMTP_MAX_MESSAGE_BYTES` | `52428800` | Inbound message size ceiling |

## Development

```sh
uv venv && uv pip install -e '.[dev]'
pytest
ruff check .
```

## License

[MIT](LICENSE)
