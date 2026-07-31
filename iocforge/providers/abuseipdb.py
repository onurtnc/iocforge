"""AbuseIPDB - IP adresi itibar sorgusu."""
from __future__ import annotations

from ..http import get_json
from .base import Provider, ProviderResult

CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class AbuseIPDB(Provider):
    name = "AbuseIPDB"
    requires_key = True
    key_env = "ABUSEIPDB_API_KEY"
    site = "https://www.abuseipdb.com"
    supports = ("ipv4", "ipv6")
    min_interval = 1.0

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        data = get_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key},
            params={"ipAddress": indicator, "maxAgeInDays": "90", "verbose": ""},
            rate_key="abuseipdb", min_interval=self.min_interval)
        payload = data.get("data") or {}
        confidence = int(payload.get("abuseConfidenceScore", 0))
        reports = int(payload.get("totalReports", 0))

        labels = []
        for report in (payload.get("reports") or [])[:5]:
            for category in report.get("categories", []):
                label = CATEGORIES.get(category)
                if label and label not in labels:
                    labels.append(label)
        if payload.get("isTor"):
            labels.append("Tor cikis dugumu")

        detail = (f"guven skoru %{confidence}, {reports} rapor, "
                  f"ulke: {payload.get('countryCode') or '?'}, "
                  f"ISP: {payload.get('isp') or '?'}")
        return ProviderResult(
            provider=self.name, indicator=indicator,
            found=reports > 0 or confidence > 0,
            malicious=confidence >= 25,
            score=confidence, labels=labels[:5], detail=detail,
            link=f"{self.site}/check/{indicator}",
            raw={"confidence": confidence, "reports": reports,
                 "country": payload.get("countryCode"), "isp": payload.get("isp"),
                 "usage": payload.get("usageType")},
        )
