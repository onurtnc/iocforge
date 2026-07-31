"""GreyNoise Community API - IP internet gurultusu mu, hedefli mi?"""
from __future__ import annotations

from ..http import HttpError, get_json
from .base import Provider, ProviderResult


class GreyNoise(Provider):
    name = "GreyNoise"
    requires_key = False        # community endpoint anahtarsiz calisir
    key_env = "GREYNOISE_API_KEY"
    site = "https://viz.greynoise.io"
    supports = ("ipv4",)
    min_interval = 1.0

    def _query(self, indicator: str, ioc_type: str) -> ProviderResult:
        headers = {"key": self.api_key} if self.api_key else {}
        try:
            data = get_json(
                f"https://api.greynoise.io/v3/community/{indicator}",
                headers=headers, rate_key="greynoise", min_interval=self.min_interval)
        except HttpError as exc:
            if exc.status == 404:
                return ProviderResult(
                    self.name, indicator, found=False,
                    detail="GreyNoise kayitlarinda yok (hedefli olabilir)",
                    link=f"{self.site}/ip/{indicator}")
            raise

        classification = str(data.get("classification") or "unknown")
        noise = bool(data.get("noise"))
        riot = bool(data.get("riot"))
        score = {"malicious": 85, "suspicious": 55,
                 "benign": 5, "unknown": 20}.get(classification, 20)
        labels = []
        if data.get("name") and data["name"] != "unknown":
            labels.append(str(data["name"]))
        if riot:
            labels.append("bilinen mesru servis (RIOT)")
            score = min(score, 5)
        if noise:
            labels.append("internet tarama gurultusu")

        return ProviderResult(
            provider=self.name, indicator=indicator, found=True,
            malicious=classification == "malicious",
            score=score, labels=labels,
            detail=(f"siniflandirma: {classification}"
                    + (", son goruldu: " + str(data["last_seen"])
                       if data.get("last_seen") else "")),
            link=data.get("link") or f"{self.site}/ip/{indicator}",
            raw={"classification": classification, "noise": noise, "riot": riot},
        )
