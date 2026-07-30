"""Identify the owner of a sending IP.

A report tells you which mailbox provider *reported* the mail; it does not
tell you whose machine sent it. A message reported by Google may have been
sent by Twilio SendGrid, Microsoft, a hosting provider, or a home
connection. Two public sources answer that, both free and keyless:

- reverse DNS (PTR), e.g. wfbtxdkd.outbound-mail.sendgrid.net
- RDAP, the registries' HTTPS successor to whois, giving the network name
  and the organisation it is registered to

Results are cached in the database and reused across reports: the same
handful of IPs appear in report after report.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from dmarc_service.db.models import IpIntel

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/ip/{ip}"
LOOKUP_TIMEOUT = 4.0
# Registries rate-limit bursts; a few at a time resolves everything reliably.
MAX_PARALLEL = 4


def _ptr(ip: str) -> str:
    import dns.resolver
    import dns.reversename

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = LOOKUP_TIMEOUT
    try:
        answers = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:  # noqa: BLE001 - no PTR is normal, not an error
        return ""


def _rdap(ip: str) -> tuple[str, str]:
    """Returns (netname, organisation)."""
    try:
        response = httpx.get(
            RDAP_URL.format(ip=ip), timeout=LOOKUP_TIMEOUT, follow_redirects=True
        )
        response.raise_for_status()
        data = response.json()
    except Exception:  # noqa: BLE001 - registry down or rate limiting
        return "", ""

    netname = (data.get("name") or "")[:128]

    # Registries list several contacts per network. Prefer the party the
    # network is registered to, and prefer organisations over the individual
    # admins some registries expose, so an IP reads "Microsoft" not the name
    # of whoever happens to be the technical contact.
    # Abuse contacts are never the owner ("Abuse-C Role" and friends), so
    # they rank below everything, as do role objects and individuals.
    role_rank = {"registrant": 0, "administrative": 1, "technical": 2, "abuse": 30}
    role_words = ("role", "abuse", "noc", "hostmaster", "postmaster", "registry")
    best_score, org = 99, ""
    for entity in data.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            continue
        name, kind = "", ""
        for item in vcard[1]:
            if len(item) >= 4 and item[0] == "fn" and item[3]:
                name = str(item[3])[:255]
            elif len(item) >= 4 and item[0] == "kind":
                kind = str(item[3]).lower()
        if not name:
            continue
        score = min((role_rank.get(r, 8) for r in entity.get("roles") or []), default=8)
        if kind == "individual":
            score += 10  # a person is a last resort
        if any(word in name.lower() for word in role_words):
            score += 20  # a contact role, not the organisation
        if score < best_score:
            best_score, org = score, name

    # Nothing but contact objects: the network name identifies the owner better
    if best_score >= 20:
        org = ""
    return netname, org


def lookup(ip: str) -> dict:
    ptr = _ptr(ip)
    netname, org = _rdap(ip)
    return {"ip": ip, "ptr": ptr, "netname": netname, "org": org}


def enrich_ips(session: Session, ips: list[str], limit: int = 25) -> dict[str, IpIntel]:
    """Return cached intel for ips, resolving the ones not seen before.

    At most `limit` new IPs are resolved per call so a page load stays fast;
    the rest are picked up on a later view or by `dmarc-service enrich`.
    """
    wanted = [ip for ip in dict.fromkeys(ips) if ip]
    if not wanted:
        return {}

    cached = {
        row.ip: row for row in session.scalars(select(IpIntel).where(IpIntel.ip.in_(wanted)))
    }
    # A row with a PTR but no registry data came from a throttled lookup;
    # retry those rather than showing a half answer forever.
    incomplete = [ip for ip, row in cached.items() if not row.org and not row.netname]
    todo = ([ip for ip in wanted if ip not in cached] + incomplete)[:limit]
    if not todo:
        return cached

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        for result in pool.map(lookup, todo):
            if not any((result["ptr"], result["netname"], result["org"])):
                continue  # nothing learned; leave it for a later retry
            row = cached.get(result["ip"]) or IpIntel(ip=result["ip"])
            row.ptr = result["ptr"] or row.ptr
            row.netname = result["netname"] or row.netname
            row.org = result["org"] or row.org
            session.add(row)
            cached[row.ip] = row
    session.flush()
    return cached


def describe(intel: IpIntel | None) -> str:
    """One short human label for an IP: the organisation if the registry
    knows one, else the network name, else the PTR host."""
    if intel is None:
        return ""
    return intel.org or intel.netname or intel.ptr


def backfill(session: Session, limit: int = 500) -> int:
    """Resolve every source IP seen in reports that has no intel yet."""
    from dmarc_service.db.models import AggregateRecord

    ips = list(
        session.scalars(
            select(AggregateRecord.source_ip)
            .distinct()
            .outerjoin(IpIntel, IpIntel.ip == AggregateRecord.source_ip)
            .where((IpIntel.id.is_(None)) | ((IpIntel.org == "") & (IpIntel.netname == "")))
            .limit(limit)
        )
    )
    if not ips:
        return 0
    enrich_ips(session, ips, limit=len(ips))
    return len(ips)
