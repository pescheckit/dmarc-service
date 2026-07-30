"""Parsers for report payloads.

Aggregate DMARC reports arrive as XML, usually gzip- or zip-compressed,
attached to email. TLS-RPT reports are JSON (possibly gzipped), delivered by
mail or POSTed over HTTPS. Everything here is defensive: sender input is
untrusted (defusedxml, size-capped upstream, zip taken one member at a time).
"""

import gzip
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import Message

from defusedxml import ElementTree


@dataclass
class ParsedAggregateRecord:
    source_ip: str
    count: int
    disposition: str
    dkim_result: str
    spf_result: str
    header_from: str
    envelope_from: str = ""
    auth_dkim_domain: str = ""
    auth_dkim_result: str = ""
    auth_spf_domain: str = ""
    auth_spf_result: str = ""


@dataclass
class ParsedAggregateReport:
    org_name: str
    org_email: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    policy_domain: str
    policy_adkim: str = "r"
    policy_aspf: str = "r"
    policy_p: str = "none"
    policy_sp: str = ""
    policy_pct: int = 100
    records: list[ParsedAggregateRecord] = field(default_factory=list)


@dataclass
class ParsedTlsReport:
    organization_name: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    contact_info: str
    body: str  # full report JSON, verbatim
    policy_domains: list[str] = field(default_factory=list)


def _text(element, path: str, default: str = "") -> str:
    found = element.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def _epoch(value: str) -> datetime:
    return datetime.fromtimestamp(int(float(value)), tz=UTC)


def _strip_namespaces(root):
    """Some reporters (GMX/web.de and other United Internet brands) wrap the
    report in an XML namespace, which would make every plain find() miss."""
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def parse_aggregate_xml(data: bytes) -> ParsedAggregateReport:
    root = _strip_namespaces(ElementTree.fromstring(data))
    if root.tag != "feedback":
        # occasionally the report is wrapped in an outer element
        nested = root.find(".//feedback")
        if nested is not None:
            root = nested

    metadata = root.find("report_metadata")
    policy = root.find("policy_published")
    if metadata is None and policy is None:
        raise ValueError(
            f"not a DMARC aggregate report: <{root.tag}> has neither "
            "report_metadata nor policy_published"
        )

    # Be lenient about the parts that are only bookkeeping: a report with
    # records is worth keeping even when a sender omits some metadata.
    org_name = _text(metadata, "org_name") if metadata is not None else ""
    report_id = _text(metadata, "report_id") if metadata is not None else ""
    if not report_id:
        report_id = hashlib.sha256(data).hexdigest()[:32]

    policy_domain = _text(policy, "domain").lower() if policy is not None else ""
    if not policy_domain:
        identifiers = root.find("record/identifiers")
        policy_domain = _text(identifiers, "header_from").lower() if identifiers is not None else ""

    report = ParsedAggregateReport(
        org_name=org_name or "unknown",
        org_email=_text(metadata, "email") if metadata is not None else "",
        report_id=report_id,
        date_begin=_epoch(_text(metadata, "date_range/begin", "0") if metadata is not None else "0"),
        date_end=_epoch(_text(metadata, "date_range/end", "0") if metadata is not None else "0"),
        policy_domain=policy_domain,
        policy_adkim=_text(policy, "adkim", "r") if policy is not None else "r",
        policy_aspf=_text(policy, "aspf", "r") if policy is not None else "r",
        policy_p=_text(policy, "p", "none") if policy is not None else "none",
        policy_sp=_text(policy, "sp") if policy is not None else "",
        policy_pct=int((_text(policy, "pct", "100") if policy is not None else "100") or 100),
    )

    for row_parent in root.findall("record"):
        row = row_parent.find("row")
        identifiers = row_parent.find("identifiers")
        auth = row_parent.find("auth_results")
        if row is None:
            continue
        evaluated = row.find("policy_evaluated")
        record = ParsedAggregateRecord(
            source_ip=_text(row, "source_ip"),
            count=int(_text(row, "count", "0") or 0),
            disposition=_text(evaluated, "disposition", "none") if evaluated is not None else "none",
            dkim_result=_text(evaluated, "dkim") if evaluated is not None else "",
            spf_result=_text(evaluated, "spf") if evaluated is not None else "",
            header_from=_text(identifiers, "header_from").lower() if identifiers is not None else "",
            envelope_from=_text(identifiers, "envelope_from").lower() if identifiers is not None else "",
        )
        if auth is not None:
            dkim = auth.find("dkim")
            spf = auth.find("spf")
            if dkim is not None:
                record.auth_dkim_domain = _text(dkim, "domain").lower()
                record.auth_dkim_result = _text(dkim, "result")
            if spf is not None:
                record.auth_spf_domain = _text(spf, "domain").lower()
                record.auth_spf_result = _text(spf, "result")
        report.records.append(record)

    return report


def parse_tlsrpt_json(data: bytes) -> ParsedTlsReport:
    body = json.loads(data)
    date_range = body.get("date-range", {})
    policies = body.get("policies", [])
    domains = []
    for item in policies:
        domain = item.get("policy", {}).get("policy-domain", "")
        if domain:
            domains.append(domain.lower())
    return ParsedTlsReport(
        organization_name=body.get("organization-name", ""),
        report_id=body.get("report-id", ""),
        date_begin=_parse_rfc3339(date_range.get("start-datetime", "")),
        date_end=_parse_rfc3339(date_range.get("end-datetime", "")),
        contact_info=body.get("contact-info", ""),
        body=json.dumps(body),
        policy_domains=domains,
    )


def _parse_rfc3339(value: str) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    return datetime.fromisoformat(value)


def decompress(payload: bytes, filename: str = "") -> list[bytes]:
    """Return the report document(s) contained in an attachment payload."""
    name = filename.lower()
    if payload[:2] == b"\x1f\x8b" or name.endswith((".gz", ".gzip")):
        return [gzip.decompress(payload)]
    if payload[:4] == b"PK\x03\x04" or name.endswith(".zip"):
        out = []
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                out.append(archive.read(info))
        return out
    return [payload]


def extract_report_payloads(message: Message) -> list[bytes]:
    """Walk a MIME message and return every candidate report document."""
    payloads: list[bytes] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        content = part.get_payload(decode=True)
        if not content:
            continue
        content_type = part.get_content_type()
        filename = part.get_filename() or ""
        if content_type.startswith("text/plain") and not filename:
            # Report bodies commonly ship a human-readable text part; skip it
            # unless it actually looks like a report document.
            stripped = content.lstrip()
            if not stripped.startswith((b"<", b"{")):
                continue
        try:
            payloads.extend(decompress(content, filename))
        except (OSError, zipfile.BadZipFile, EOFError):
            continue
    return payloads


def classify(document: bytes) -> str:
    """aggregate | tlsrpt | unknown"""
    stripped = document.lstrip()
    if stripped.startswith(b"<"):
        head = stripped[:2000]
        if b"<feedback" in head or b"report_metadata" in head:
            return "aggregate"
        return "unknown"
    if stripped.startswith(b"{"):
        try:
            head = json.loads(stripped)
        except json.JSONDecodeError:
            return "unknown"
        if "organization-name" in head or "policies" in head:
            return "tlsrpt"
    return "unknown"
