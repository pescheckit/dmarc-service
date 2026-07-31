"""Prometheus metrics, on a listener of their own.

These are deliberately not mounted on the web app's router. The labels name
every tenant and domain on the instance, say which of them currently have no
working DMARC record, and say which are close to the SPF lookup limit. That
is a target list for anyone wanting to spoof your customers, and the web app
is usually published to the internet. So metrics get:

- their own port, which no ingress or reverse proxy should route to
- a bearer token, required unless the operator opts out explicitly
- an option to drop the identifying labels and publish only totals

Every value is read from the database rather than counted in memory, so any
process (web, smtp, imap) reports the same numbers and there is no
multiprocess counter state to reconcile. The DNS and SPF gauges come from a
background refresh: a scrape reads the last result and never waits on a
lookup.
"""

import logging
import secrets
import threading
import time
from datetime import UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.process_collector import ProcessCollector
from sqlalchemy import func, select

from dmarc_service.config import get_settings

logger = logging.getLogger(__name__)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("dmarc-service")
    except PackageNotFoundError:  # running from a source tree without install
        return "unknown"


def _epoch(value) -> float | None:
    """Timestamp as seconds since the epoch, tolerating naive datetimes
    (SQLite hands back what it was given, without a timezone)."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


# --- background DNS/SPF checks ---


class DnsSnapshot:
    """Last known DNS and SPF state per domain, refreshed on a timer.

    Checking on scrape would be wrong twice over: a cold cache would make
    Prometheus wait seconds for a dozen sequential lookups, and the scrape
    interval would decide how hard we hammer other people's nameservers.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[tuple[str, str, str]] = []  # (domain, record name, status)
        self._spf: dict[str, int] = {}  # domain -> lookups consumed
        self._updated: float = 0.0

    def read(self) -> tuple[list[tuple[str, str, str]], dict[str, int], float]:
        with self._lock:
            return list(self._records), dict(self._spf), self._updated

    def refresh(self) -> None:
        from dmarc_service.control_plane import service as control_plane
        from dmarc_service.db.models import Domain
        from dmarc_service.db.session import session_scope
        from dmarc_service.ingest import spf

        records: list[tuple[str, str, str]] = []
        lookups: dict[str, int] = {}
        with session_scope() as db:
            domains = list(db.scalars(select(Domain).order_by(Domain.name)))
            for domain in domains:
                expected = control_plane.required_dns_records(db, domain)
                for checked in control_plane.check_dns_records(expected):
                    records.append((domain.name, checked["name"], checked["status"]))
                try:
                    lookups[domain.name] = spf.expand_with_cost(domain.name)[1]
                except Exception:  # noqa: BLE001 - one bad record must not stop the rest
                    logger.info("SPF expansion failed for %s", domain.name)

        with self._lock:
            self._records, self._spf, self._updated = records, lookups, time.time()

    def run(self, interval: int) -> None:
        while True:
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - a resolver outage must not end the loop
                logger.exception("DNS metrics refresh failed; retrying")
            time.sleep(interval)


# --- collector ---


class DatabaseCollector:
    def __init__(self, snapshot: DnsSnapshot | None = None) -> None:
        self.snapshot = snapshot

    def collect(self):
        settings = get_settings()
        try:
            metrics = list(self._collect(settings))
            up = 1.0
        except Exception:  # noqa: BLE001 - a scrape must not 500 on a database blip
            logger.exception("metrics collection failed")
            metrics, up = [], 0.0

        yield GaugeMetricFamily(
            "dmarc_collector_up",
            "1 when the last scrape could read the database",
            value=up,
        )
        yield from metrics

    def _collect(self, settings):
        from dmarc_service.db.models import (
            UNROUTED_TENANT_SLUG,
            AggregateRecord,
            AggregateReport,
            Domain,
            ImapAccount,
            RawMessage,
            Tenant,
            TlsReport,
        )
        from dmarc_service.db.session import session_scope

        labels = settings.metrics_labels

        info = GaugeMetricFamily(
            "dmarc_build_info", "Version of the running service", labels=["version"]
        )
        info.add_metric([_version()], 1)
        yield info

        with session_scope() as db:
            tenants = GaugeMetricFamily(
                "dmarc_tenants", "Tenants configured, excluding the unrouted quarantine"
            )
            tenants.add_metric(
                [], db.scalar(
                    select(func.count(Tenant.id)).where(Tenant.slug != UNROUTED_TENANT_SLUG)
                ) or 0
            )
            yield tenants

            domains = GaugeMetricFamily("dmarc_domains", "Domains being monitored")
            domains.add_metric([], db.scalar(select(func.count(Domain.id))) or 0)
            yield domains

            received = CounterMetricFamily(
                "dmarc_messages_received",
                "Report messages accepted, by what routing decided about them",
                labels=["status"],
            )
            for status, count in db.execute(
                select(RawMessage.status, func.count(RawMessage.id)).group_by(RawMessage.status)
            ):
                received.add_metric([status], count)
            yield received

            unrouted = GaugeMetricFamily(
                "dmarc_unrouted_messages",
                "Messages held in the quarantine because no active address claimed them",
            )
            unrouted.add_metric(
                [],
                db.scalar(
                    select(func.count(RawMessage.id)).where(RawMessage.status == "unrouted")
                ) or 0,
            )
            yield unrouted

            reports = CounterMetricFamily(
                "dmarc_reports_parsed", "Reports stored, by kind", labels=["kind"]
            )
            reports.add_metric(
                ["aggregate"], db.scalar(select(func.count(AggregateReport.id))) or 0
            )
            reports.add_metric(["tls"], db.scalar(select(func.count(TlsReport.id))) or 0)
            yield reports

            yield from self._message_counts(db, AggregateRecord, AggregateReport, labels)
            yield from self._freshness(db, AggregateReport, labels)
            yield from self._mailboxes(db, ImapAccount, labels)

        yield from self._dns(labels)

    def _message_counts(self, db, AggregateRecord, AggregateReport, labels):
        """Messages senders reported on, split by whether DMARC passed.

        Source IP is deliberately not a label: a busy domain sees tens of
        thousands of them, and one careless label would take the whole
        Prometheus down with it.
        """
        query = select(
            AggregateReport.policy_domain,
            AggregateRecord.disposition,
            AggregateRecord.dkim_result,
            AggregateRecord.spf_result,
            func.sum(AggregateRecord.count),
        ).join(AggregateReport).group_by(
            AggregateReport.policy_domain,
            AggregateRecord.disposition,
            AggregateRecord.dkim_result,
            AggregateRecord.spf_result,
        )

        by_result: dict[tuple[str, str], int] = {}
        by_disposition: dict[tuple[str, str], int] = {}
        for domain, disposition, dkim, spf_result, total in db.execute(query):
            total = int(total or 0)
            key_domain = domain if labels else ""
            # policy_evaluated already carries the alignment verdict, so a
            # pass on either mechanism is a DMARC pass.
            result = "pass" if "pass" in (dkim, spf_result) else "fail"
            by_result[(key_domain, result)] = by_result.get((key_domain, result), 0) + total
            key = (key_domain, disposition or "none")
            by_disposition[key] = by_disposition.get(key, 0) + total

        names = ["domain", "result"] if labels else ["result"]
        family = CounterMetricFamily(
            "dmarc_messages_reported",
            "Messages covered by aggregate reports, by DMARC verdict",
            labels=names,
        )
        for (domain, result), total in sorted(by_result.items()):
            family.add_metric([domain, result] if labels else [result], total)
        yield family

        names = ["domain", "disposition"] if labels else ["disposition"]
        family = CounterMetricFamily(
            "dmarc_messages_disposition",
            "Messages covered by aggregate reports, by what the receiver did with them",
            labels=names,
        )
        for (domain, disposition), total in sorted(by_disposition.items()):
            family.add_metric([domain, disposition] if labels else [disposition], total)
        yield family

    def _freshness(self, db, AggregateReport, labels):
        """When each domain was last reported on.

        The one metric here that cannot be replaced by looking at the UI:
        senders report daily, so silence means reports are being lost, and
        a screen that only shows what did arrive cannot tell you that.
        """
        rows = db.execute(
            select(AggregateReport.policy_domain, func.max(AggregateReport.date_end))
            .group_by(AggregateReport.policy_domain)
        ).all()

        if labels:
            family = GaugeMetricFamily(
                "dmarc_last_report_timestamp_seconds",
                "End of the most recent reporting period, per domain",
                labels=["domain"],
            )
            for domain, latest in sorted(rows):
                stamp = _epoch(latest)
                if stamp is not None:
                    family.add_metric([domain], stamp)
        else:
            newest = max((_epoch(latest) or 0.0 for _, latest in rows), default=0.0)
            family = GaugeMetricFamily(
                "dmarc_last_report_timestamp_seconds",
                "End of the most recent reporting period across all domains",
            )
            family.add_metric([], newest)
        yield family

    def _mailboxes(self, db, ImapAccount, labels):
        accounts = list(db.scalars(select(ImapAccount).order_by(ImapAccount.id)))
        enabled = [a for a in accounts if a.enabled]

        total = GaugeMetricFamily("dmarc_imap_mailboxes", "IMAP mailboxes being polled")
        total.add_metric([], len(enabled))
        yield total

        if not labels:
            failing = GaugeMetricFamily(
                "dmarc_imap_mailboxes_failing", "Mailboxes whose last poll reported an error"
            )
            failing.add_metric([], sum(1 for a in enabled if _poll_failed(a)))
            yield failing
            oldest = min((_epoch(a.last_polled_at) or 0.0 for a in enabled), default=0.0)
            stamp = GaugeMetricFamily(
                "dmarc_imap_last_poll_timestamp_seconds",
                "Oldest successful poll across all mailboxes",
            )
            stamp.add_metric([], oldest)
            yield stamp
            return

        # The label is the mailbox address, which is why it follows
        # metrics_labels: it is a real address belonging to a real person.
        ok = GaugeMetricFamily(
            "dmarc_imap_poll_ok", "1 when the last poll of this mailbox succeeded",
            labels=["mailbox"],
        )
        stamp = GaugeMetricFamily(
            "dmarc_imap_last_poll_timestamp_seconds", "When this mailbox was last polled",
            labels=["mailbox"],
        )
        for account in enabled:
            ok.add_metric([account.username], 0 if _poll_failed(account) else 1)
            polled = _epoch(account.last_polled_at)
            if polled is not None:
                stamp.add_metric([account.username], polled)
        yield ok
        yield stamp

    def _dns(self, labels):
        if self.snapshot is None:
            return
        records, lookups, updated = self.snapshot.read()

        age = GaugeMetricFamily(
            "dmarc_dns_check_timestamp_seconds", "When DNS and SPF were last checked"
        )
        age.add_metric([], updated)
        yield age
        if not updated:
            return  # first refresh has not finished; publish nothing rather than zeros

        published = sum(1 for _, _, status in records if status == "ok")
        totals = GaugeMetricFamily(
            "dmarc_dns_records_expected", "Records the service expects to be published"
        )
        totals.add_metric([], len(records))
        yield totals
        totals = GaugeMetricFamily(
            "dmarc_dns_records_published", "Expected records confirmed live in DNS"
        )
        totals.add_metric([], published)
        yield totals

        if labels:
            family = GaugeMetricFamily(
                "dmarc_dns_record_ok",
                "1 when this record is published as expected, 0 otherwise",
                labels=["domain", "record", "status"],
            )
            for domain, name, status in records:
                family.add_metric([domain, name, status], 1 if status == "ok" else 0)
            yield family

            family = GaugeMetricFamily(
                "dmarc_spf_lookups",
                "DNS lookups this domain's SPF record consumes, of the ten allowed",
                labels=["domain"],
            )
            for domain, used in sorted(lookups.items()):
                family.add_metric([domain], used)
            yield family
        else:
            worst = max(lookups.values(), default=0)
            family = GaugeMetricFamily(
                "dmarc_spf_lookups_max",
                "Highest SPF lookup count across all domains, of the ten allowed",
            )
            family.add_metric([], worst)
            yield family

        limit = GaugeMetricFamily(
            "dmarc_spf_lookup_limit", "Lookups RFC 7208 permits before SPF stops evaluating"
        )
        limit.add_metric([], 10)
        yield limit


def _poll_failed(account) -> bool:
    """last_result holds a summary on success and an error string otherwise."""
    return bool(account.last_result) and "stored" not in account.last_result


# --- exposition ---


def build_registry(snapshot: DnsSnapshot | None = None) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(DatabaseCollector(snapshot))
    ProcessCollector(registry=registry)
    return registry


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        if self.path.split("?")[0] not in ("/metrics", "/"):
            self._respond(404, b"not found\n", "text/plain")
            return
        if not self.server.authorized(self.headers.get("Authorization", "")):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="metrics"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond(200, generate_latest(self.server.registry), CONTENT_TYPE)

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        """Prometheus scrapes every few seconds; that is not news."""


class MetricsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, registry, token: str) -> None:
        super().__init__(address, _Handler)
        self.registry = registry
        self.token = token

    def authorized(self, header: str) -> bool:
        if not self.token:
            return True
        presented = header.removeprefix("Bearer ").strip()
        return secrets.compare_digest(presented, self.token)


def serve(*, dns_checks: bool = False) -> MetricsServer | None:
    """Start the metrics listener, if it is enabled.

    Refuses to run unauthenticated by accident: enabling metrics without a
    token stops the process rather than quietly publishing your tenant list.
    """
    settings = get_settings()
    if not settings.metrics_enabled:
        return None
    if not settings.metrics_token and not settings.metrics_allow_unauthenticated:
        raise RuntimeError(
            "METRICS_ENABLED is set but METRICS_TOKEN is empty. These metrics name "
            "your tenants and domains and show which of them have no working DMARC "
            "record. Set METRICS_TOKEN, or set METRICS_ALLOW_UNAUTHENTICATED=true if "
            "the port is genuinely unreachable from anywhere untrusted."
        )

    snapshot = None
    if dns_checks:
        snapshot = DnsSnapshot()
        threading.Thread(
            target=snapshot.run,
            args=(settings.metrics_dns_interval,),
            name="metrics-dns",
            daemon=True,
        ).start()

    server = MetricsServer(
        (settings.metrics_host, settings.metrics_port),
        build_registry(snapshot),
        settings.metrics_token,
    )
    threading.Thread(target=server.serve_forever, name="metrics", daemon=True).start()
    logger.info(
        "metrics on %s:%s (%s)",
        settings.metrics_host,
        settings.metrics_port,
        "token required" if settings.metrics_token else "UNAUTHENTICATED",
    )
    return server
