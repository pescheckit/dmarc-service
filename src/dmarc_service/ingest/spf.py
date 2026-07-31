"""Expand a domain's SPF record into the IP ranges it authorises.

A DMARC report says whether a message passed; it does not say whether the
sender is one you have declared. Expanding your own `v=spf1` record answers
that: every `include:`, `a`, `mx` and `ip4`/`ip6` term resolves to concrete
networks, and a source IP either falls inside them or does not.

Three verdicts come out of it:

- authorized: inside your published SPF, a sender you have declared
- aligned:    not in SPF but authenticated as your domain (usually a vendor
              set up for DKIM but forgotten in SPF)
- unknown:    neither, which is the row worth looking at

Lookups are bounded the way RFC 7208 bounds them (10 DNS-querying terms), so
a hostile or looping record cannot spin here forever.
"""

import ipaddress
import logging

logger = logging.getLogger(__name__)

MAX_DNS_TERMS = 10  # RFC 7208 section 4.6.4


def _resolver():
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 4.0
    return resolver


def _txt(resolver, name: str) -> list[str]:
    try:
        return ["".join(s.decode() for s in r.strings) for r in resolver.resolve(name, "TXT")]
    except Exception:  # noqa: BLE001 - absent record is a normal answer
        return []


def _addresses(resolver, name: str) -> list[str]:
    out = []
    for rtype in ("A", "AAAA"):
        try:
            out.extend(str(r) for r in resolver.resolve(name, rtype))
        except Exception:  # noqa: BLE001
            continue
    return out


def spf_record(domain: str, resolver=None) -> str:
    resolver = resolver or _resolver()
    for value in _txt(resolver, domain):
        if value.lower().startswith("v=spf1"):
            return value
    return ""


def expand(domain: str, resolver=None) -> list[ipaddress._BaseNetwork]:
    """All networks authorised by the domain's SPF record."""
    return expand_with_cost(domain, resolver)[0]


def expand_with_cost(domain: str, resolver=None) -> tuple[list[ipaddress._BaseNetwork], int]:
    """Expansion, plus how many of the ten permitted lookups it consumed.

    The cost is worth knowing on its own: a record sitting at nine is one
    vendor away from exceeding the limit, at which point receivers stop
    evaluating SPF entirely and every unsigned message starts failing.
    """
    resolver = resolver or _resolver()
    networks: list[ipaddress._BaseNetwork] = []
    budget = [MAX_DNS_TERMS]
    seen: set[str] = set()

    def walk(name: str) -> None:
        if budget[0] <= 0 or name in seen:
            return
        seen.add(name)
        record = spf_record(name, resolver)
        if not record:
            return

        for term in record.split()[1:]:
            if budget[0] <= 0:
                return
            term = term.lstrip("+")
            lowered = term.lower()
            try:
                if lowered.startswith("ip4:") or lowered.startswith("ip6:"):
                    networks.append(ipaddress.ip_network(term.split(":", 1)[1], strict=False))
                elif lowered.startswith("include:") or lowered.startswith("redirect="):
                    budget[0] -= 1
                    walk(term.split(":", 1)[-1].split("=", 1)[-1])
                elif lowered == "a" or lowered.startswith("a:"):
                    budget[0] -= 1
                    host = term.split(":", 1)[1] if ":" in term else name
                    for address in _addresses(resolver, host):
                        networks.append(ipaddress.ip_network(address))
                elif lowered == "mx" or lowered.startswith("mx:"):
                    budget[0] -= 1
                    host = term.split(":", 1)[1] if ":" in term else name
                    try:
                        exchanges = [str(r.exchange).rstrip(".")
                                     for r in resolver.resolve(host, "MX")]
                    except Exception:  # noqa: BLE001
                        exchanges = []
                    for exchange in exchanges[:5]:
                        for address in _addresses(resolver, exchange):
                            networks.append(ipaddress.ip_network(address))
            except ValueError:
                logger.info("ignoring malformed SPF term %r in %s", term, name)

    walk(domain)
    return networks, MAX_DNS_TERMS - max(budget[0], 0)


# Expansion costs up to ten DNS lookups, so keep the result briefly.
CACHE_TTL = 3600.0
_cache: dict[str, tuple[float, list]] = {}


def clear_cache() -> None:
    _cache.clear()


def cached_expand(domain: str) -> list:
    import time

    hit = _cache.get(domain)
    if hit and time.monotonic() - hit[0] < CACHE_TTL:
        return hit[1]
    networks = expand(domain)
    _cache[domain] = (time.monotonic(), networks)
    return networks


def contains(networks: list, ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks
               if network.version == address.version)


def classify(networks: list, ip: str, *, aligned: bool) -> str:
    """authorized | aligned | unknown for one sending source."""
    if contains(networks, ip):
        return "authorized"
    return "aligned" if aligned else "unknown"
