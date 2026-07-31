"""Serbest metinden IOC (gosterge) cikarir. Defang edilmis girdileri de anlar."""
from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Dict, Iterable, List

# Defang kaliplarini normale cevirme
_REFANG_RULES = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s+\.\s+|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]|\(:\)|\[colon\]", re.I), ":"),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\bh(?:xx|X{2})p(s?)://", re.I), r"http\1://"),
    (re.compile(r"\bmeow(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[//\]", re.I), "//"),
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\)\]]+", re.I)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,24})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Gurultu azaltma: teknik dosya uzantilari alan adi gibi gorunur
_FILE_TLDS = {
    "exe", "dll", "php", "html", "htm", "js", "py", "txt", "log", "json", "xml",
    "png", "jpg", "jpeg", "gif", "css", "zip", "rar", "doc", "docx", "xls",
    "xlsx", "pdf", "ps1", "bat", "sh", "conf", "ini", "yml", "yaml", "md",
    "csv", "bin", "dat", "tmp", "bak", "old", "sys", "inf", "cab", "msi",
    "docm", "xlsm", "pptm", "dotm", "ppt", "pptx", "rtf", "odt", "ods",
    "eml", "msg", "pcap", "pcapng", "evtx", "reg", "vbs", "hta", "jar",
    "iso", "img", "vhd", "lnk", "scr", "cmd", "com", "chm", "svg", "ico",
    "woff", "ttf", "mp3", "mp4", "avi", "gz", "tgz", "7z", "tar", "db",
    "so", "o", "a", "class", "jsp", "asp", "aspx", "cgi", "pl", "rb", "go",
    "rs", "ts", "tsx", "jsx", "vue", "scss", "less", "lock", "toml", "cfg",
}
_NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "test.com",
    "w3.org", "schemas.microsoft.com", "www.w3.org",
}


def refang(text: str) -> str:
    """`hxxp://evil[.]com` -> `http://evil.com`"""
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def defang(value: str) -> str:
    """Tiklanamaz hale getirir."""
    return (value.replace("http://", "hxxp://").replace("https://", "hxxps://")
                 .replace(".", "[.]").replace("@", "[at]"))


def _valid_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_multicast)


def is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_link_local or address.is_reserved


def _valid_domain(value: str) -> bool:
    value = value.lower().rstrip(".")
    if value in _NOISE_DOMAINS or len(value) > 253:
        return False
    parts = value.split(".")
    if len(parts) < 2 or parts[-1] in _FILE_TLDS or parts[-1].isdigit():
        return False
    if len(parts[-1]) < 2 or not parts[-1].isalpha():
        return False
    # "2026-88412.docm" gibi dosya adlarini eleme: etiketlerin tamami rakam/tire olmasin
    if all(re.fullmatch(r"[\d-]+", p) for p in parts[:-1]):
        return False
    return all(1 <= len(p) <= 63 for p in parts)


def extract(text: str, include_private: bool = False) -> Dict[str, List[str]]:
    """Metinden tur tur IOC cikarir. Sonuclar tekil ve sirali doner."""
    clean = refang(text)
    result: "OrderedDict[str, List[str]]" = OrderedDict(
        (key, []) for key in
        ("url", "domain", "ipv4", "ipv6", "md5", "sha1", "sha256", "email", "cve", "btc"))

    urls = [u.rstrip(".,;:)]}'\"") for u in URL_RE.findall(clean)]
    result["url"] = _dedupe(urls)

    hashes256 = set(SHA256_RE.findall(clean))
    hashes1 = {h for h in SHA1_RE.findall(clean)
               if not any(h in big for big in hashes256)}
    hashes5 = {h for h in MD5_RE.findall(clean)
               if not any(h in big for big in hashes256 | hashes1)}
    result["sha256"] = _dedupe(sorted(hashes256), lower=True)
    result["sha1"] = _dedupe(sorted(hashes1), lower=True)
    result["md5"] = _dedupe(sorted(hashes5), lower=True)

    emails = EMAIL_RE.findall(clean)
    result["email"] = _dedupe(emails, lower=True)

    ips = [ip for ip in IPV4_RE.findall(clean) if _valid_ip(ip)]
    if not include_private:
        ips = [ip for ip in ips if not is_private_ip(ip)]
    result["ipv4"] = _dedupe(ips)
    result["ipv6"] = _dedupe([ip for ip in IPV6_RE.findall(clean) if _valid_ip(ip)])

    email_domains = {e.split("@")[-1] for e in result["email"]}
    url_hosts = set()
    for url in result["url"]:
        match = re.match(r"(?i)\w+://([^/:?#]+)", url)
        if match:
            url_hosts.add(match.group(1).lower())
    domains = [d for d in DOMAIN_RE.findall(clean) if _valid_domain(d)]
    domains = [d for d in domains if not IPV4_RE.fullmatch(d)]
    result["domain"] = _dedupe(domains, lower=True)
    # URL ve e-posta icindeki alan adlarini da ayrica listele (kaybolmasin)
    for host in sorted(url_hosts | email_domains):
        if _valid_domain(host) and host not in result["domain"]:
            result["domain"].append(host)

    result["cve"] = _dedupe([c.upper() for c in CVE_RE.findall(clean)])
    result["btc"] = _dedupe(BTC_RE.findall(clean))
    return {k: v for k, v in result.items() if v}


def _dedupe(values: Iterable[str], lower: bool = False) -> List[str]:
    seen, out = set(), []
    for value in values:
        key = value.lower() if lower else value
        if key not in seen:
            seen.add(key)
            out.append(key if lower else value)
    return out


def guess_type(value: str) -> str:
    """Tek bir gostergenin turunu tahmin eder."""
    value = refang(value.strip())
    if URL_RE.fullmatch(value):
        return "url"
    if SHA256_RE.fullmatch(value):
        return "sha256"
    if SHA1_RE.fullmatch(value):
        return "sha1"
    if MD5_RE.fullmatch(value):
        return "md5"
    if CVE_RE.fullmatch(value):
        return "cve"
    if EMAIL_RE.fullmatch(value):
        return "email"
    if IPV4_RE.fullmatch(value) and _valid_ip(value):
        return "ipv4"
    if IPV6_RE.fullmatch(value) and _valid_ip(value):
        return "ipv6"
    if _valid_domain(value):
        return "domain"
    return "unknown"
