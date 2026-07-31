"""IOCForge ciktilari: konsol, JSON, CSV, Markdown, HTML."""
from __future__ import annotations

import csv
import html
import json
from typing import Dict, List

from .enrich import Enriched

COLORS = {"ZARARLI": "\033[97;41m", "SUPHELI": "\033[91m",
          "DUSUK RISK": "\033[93m", "TEMIZ": "\033[92m", "BILGI YOK": "\033[90m"}
HEX = {"ZARARLI": "#b3001b", "SUPHELI": "#e8590c", "DUSUK RISK": "#f08c00",
       "TEMIZ": "#2b8a3e", "BILGI YOK": "#868e96"}
RESET, BOLD = "\033[0m", "\033[1m"


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{RESET}" if use_color else text


def summarize(items: List[Enriched]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        counts[item.verdict] = counts.get(item.verdict, 0) + 1
    return counts


def to_console(items: List[Enriched], use_color: bool = True,
               verbose: bool = False) -> str:
    lines: List[str] = []
    lines.append(_c("=" * 78, BOLD, use_color))
    lines.append(_c("  IOCForge - Tehdit Istihbarati Raporu", BOLD, use_color))
    lines.append(_c("=" * 78, BOLD, use_color))
    counts = summarize(items)
    lines.append(f"  Toplam {len(items)} gosterge  |  " +
                 "  ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    lines.append("-" * 78)

    for item in sorted(items, key=lambda x: -x.score):
        verdict = item.verdict
        bar = "#" * (item.score // 10) + "." * (10 - item.score // 10)
        lines.append(_c(f"  [{verdict}]", COLORS.get(verdict, ""), use_color)
                     + f" {item.defanged}")
        lines.append(f"      tur: {item.ioc_type}   skor: [{bar}] {item.score}/100")
        if item.labels:
            lines.append(f"      etiket: {', '.join(item.labels)}")
        if item.sources_hit:
            lines.append(f"      eslesen kaynaklar: {', '.join(item.sources_hit)}")
        for note in item.notes:
            lines.append(f"      not: {note}")
        for result in item.results:
            if result.error:
                if verbose:
                    lines.append(f"      - {result.provider}: HATA {result.error}")
                continue
            mark = "!" if result.malicious else ("+" if result.found else "-")
            cached = " (onbellek)" if result.cached else ""
            lines.append(f"      {mark} {result.provider}: {result.detail}{cached}")
            if verbose and result.link:
                lines.append(f"          {result.link}")
        lines.append("")
    return "\n".join(lines)


def to_json(items: List[Enriched], include_raw: bool = False) -> str:
    return json.dumps({
        "summary": {"total": len(items), **summarize(items)},
        "indicators": [i.to_dict(include_raw) for i in items],
    }, indent=2, ensure_ascii=False)


def to_csv(items: List[Enriched], path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["indicator", "defanged", "type", "verdict", "score",
                         "labels", "sources_hit", "details"])
        for item in sorted(items, key=lambda x: -x.score):
            details = " | ".join(f"{r.provider}: {r.detail}"
                                 for r in item.results if r.found and not r.error)
            writer.writerow([item.indicator, item.defanged, item.ioc_type,
                             item.verdict, item.score, "; ".join(item.labels),
                             "; ".join(item.sources_hit), details])


def to_markdown(items: List[Enriched]) -> str:
    lines = ["# IOCForge Raporu", ""]
    counts = summarize(items)
    lines.append("| Karar | Adet |")
    lines.append("|---|---|")
    for verdict, count in sorted(counts.items()):
        lines.append(f"| {verdict} | {count} |")
    lines.append("")
    lines.append("| Gosterge | Tur | Karar | Skor | Etiketler | Kaynaklar |")
    lines.append("|---|---|---|---|---|---|")
    for item in sorted(items, key=lambda x: -x.score):
        lines.append(
            f"| `{item.defanged}` | {item.ioc_type} | **{item.verdict}** | "
            f"{item.score} | {', '.join(item.labels) or '-'} | "
            f"{', '.join(item.sources_hit) or '-'} |")
    return "\n".join(lines) + "\n"


def to_html(items: List[Enriched]) -> str:
    rows = []
    for item in sorted(items, key=lambda x: -x.score):
        color = HEX.get(item.verdict, "#868e96")
        sources = "".join(
            f"<div class='src'><b>{html.escape(r.provider)}</b>: "
            f"{html.escape(r.detail or r.error)}"
            + (f" <a href='{html.escape(r.link)}' target='_blank'>&#8599;</a>"
               if r.link else "") + "</div>"
            for r in item.results if r.found or r.error)
        rows.append(f"""<tr>
          <td><span class="v" style="background:{color}">{html.escape(item.verdict)}</span></td>
          <td><code>{html.escape(item.defanged)}</code>
              <div class='d'>{html.escape(item.ioc_type)}</div></td>
          <td class='score'>{item.score}</td>
          <td>{html.escape(', '.join(item.labels)) or '-'}</td>
          <td>{sources or '-'}</td></tr>""")

    counts = summarize(items)
    cards = "".join(f"<div class='card'><b>{v}</b><span>{html.escape(k)}</span></div>"
                    for k, v in sorted(counts.items()))
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOCForge Raporu</title><style>
 body {{ font-family:-apple-system,Segoe UI,Roboto,sans-serif; background:#0f1115;
        color:#e6e6e6; margin:0; padding:24px; }}
 h1 {{ font-size:22px; margin:0 0 16px; }}
 .cards {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:18px; }}
 .card {{ background:#171a21; border:1px solid #262b36; border-radius:10px;
          padding:12px 16px; min-width:110px; }}
 .card b {{ display:block; font-size:22px; }} .card span {{ color:#9aa0a6; font-size:11px; }}
 table {{ width:100%; border-collapse:collapse; background:#171a21;
          border:1px solid #262b36; border-radius:10px; overflow:hidden; }}
 th,td {{ padding:10px 12px; border-bottom:1px solid #262b36; text-align:left;
          font-size:13px; vertical-align:top; }}
 th {{ background:#1d222b; color:#9aa0a6; font-size:11px; text-transform:uppercase; }}
 .v {{ display:inline-block; padding:3px 10px; border-radius:20px; color:#fff;
       font-size:11px; font-weight:700; }}
 .d {{ color:#9aa0a6; font-size:11px; }} .src {{ color:#c9ced6; margin:2px 0; }}
 .score {{ font-weight:700; text-align:right; }}
 a {{ color:#5c9ded; text-decoration:none; }}
 code {{ font-family:ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }}
</style></head><body>
<h1>IOCForge - Tehdit Istihbarati Raporu</h1>
<div class="cards">{cards}</div>
<table><thead><tr><th>Karar</th><th>Gosterge</th><th>Skor</th>
<th>Etiketler</th><th>Kaynaklar</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=5>Gosterge yok.</td></tr>'}</tbody></table>
</body></html>"""
