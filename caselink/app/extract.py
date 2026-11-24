"""Pull investigative identifiers (URLs, domains, UPI IDs, phones, IPs) out of free text."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
SHORT_RE = re.compile(r"(?i)\b(?:bit\.ly|tinyurl\.com|t\.ly|cutt\.ly|rb\.gy|is\.gd)/[^\s<>\"'`]+")
UPI_HANDLES = (
    "ybl|oksbi|okhdfcbank|okicici|okaxis|paytm|apl|ibl|axl|upi|sbi|hdfcbank|icici|"
    "axisbank|fbl|pnb|barodampay|ikwik|freecharge|airtel|jio|postbank|kotak|yesbank|"
    "idfcfirst|pingpay|axisb|ptyes|pthdfc|ptsbi|okbizaxis"
)
UPI_RE = re.compile(rf"(?i)\b[a-z0-9][a-z0-9._-]{{1,}}@(?:{UPI_HANDLES})\b")
PHONE_RE = re.compile(r"(?<![\d@])(?:\+?91[\s-]?|0)?([6-9]\d{9})(?!\d)")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
BOT_RE = re.compile(r"(?i)api\.telegram\.org/bot(\d{6,12}):")

TWO_PART_SUFFIXES = {"co.in", "org.in", "gov.in", "ac.in", "nic.in", "net.in", "co.uk", "com.au", "co.za"}


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url: str) -> str:
    if not re.match(r"(?i)^https?://", url):
        url = "http://" + url
    netloc = urlparse(url).netloc
    netloc = netloc.rsplit("@", 1)[-1]
    return netloc.split(":")[0].lower().strip(".")


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?)]}>'\"")


def extract_identifiers(text: str) -> dict:
    urls = {_clean_url(m.group(0)) for m in URL_RE.finditer(text)}
    urls |= {_clean_url(m.group(0)) for m in SHORT_RE.finditer(text)}
    domains, ips = set(), set(IP_RE.findall(text))
    for u in urls:
        h = host_of(u)
        if not h:
            continue
        if IP_RE.fullmatch(h):
            ips.add(h)
        else:
            domains.add(registered_domain(h))
    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "upi_ids": sorted({m.group(0).lower() for m in UPI_RE.finditer(text)}),
        "phones": sorted({m.group(1) for m in PHONE_RE.finditer(text)}),
        "ips": sorted(ips),
        "bots": sorted(set(BOT_RE.findall(text))),
    }
