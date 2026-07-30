import gzip
import io
import zipfile

from dmarc_service.ingest import parsers


def test_parse_aggregate(aggregate_xml):
    report = parsers.parse_aggregate_xml(aggregate_xml)
    assert report.org_name == "google.com"
    assert report.report_id == "4587216196651082915"
    assert report.policy_domain == "example.com"
    assert report.policy_p == "none"
    assert report.policy_sp == "reject"
    assert len(report.records) == 2

    passing, failing = report.records
    assert passing.source_ip == "209.85.220.41"
    assert passing.count == 7
    assert passing.dkim_result == "pass"
    assert failing.disposition == "quarantine"
    assert failing.envelope_from == "bulk.spammer.example"
    assert failing.auth_spf_result == "softfail"


def test_parse_tlsrpt(tlsrpt_json):
    report = parsers.parse_tlsrpt_json(tlsrpt_json)
    assert report.organization_name == "Google Inc."
    assert report.report_id == "2026-07-21T00:00:00Z_example.com"
    assert report.policy_domains == ["example.com"]
    assert report.date_begin.year == 2026


def test_decompress_gzip(aggregate_xml):
    compressed = gzip.compress(aggregate_xml)
    assert parsers.decompress(compressed) == [aggregate_xml]


def test_decompress_zip(aggregate_xml):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("report.xml", aggregate_xml)
    assert parsers.decompress(buffer.getvalue()) == [aggregate_xml]


def test_classify(aggregate_xml, tlsrpt_json):
    assert parsers.classify(aggregate_xml) == "aggregate"
    assert parsers.classify(tlsrpt_json) == "tlsrpt"
    assert parsers.classify(b"hello world") == "unknown"
    assert parsers.classify(b"<html><body>hi</body></html>") == "unknown"


def test_xxe_is_rejected():
    evil = (
        b'<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<feedback><report_metadata><org_name>&x;</org_name></report_metadata></feedback>"
    )
    try:
        parsers.parse_aggregate_xml(evil)
    except Exception:
        return  # defusedxml refused it, good
    raise AssertionError("XXE payload was not rejected")
