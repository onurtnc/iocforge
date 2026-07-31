"""IOCForge komut satiri arayuzu."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Tuple

from . import __version__
from .cache import Cache
from .config import load_keys
from .enrich import Enricher
from .extract import extract, guess_type
from .providers import ALL_PROVIDERS
from .report import to_console, to_csv, to_html, to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iocforge",
        description="Metinden IOC cikarir, tehdit istihbarati kaynaklariyla zenginlestirir.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  iocforge 45.155.205.233
  iocforge -f rapor.txt --html rapor.html
  cat mail.eml | iocforge -                     # stdin'den oku
  iocforge -f log.txt --extract-only            # sadece IOC listesi cikar
  iocforge -f iocs.txt --free-only              # sadece anahtarsiz kaynaklar
  iocforge 1.2.3.4 --providers VirusTotal,AbuseIPDB -v

api anahtarlari (ortam degiskeni, .env veya ~/.iocforge/config.json):
  VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY
""")
    parser.add_argument("indicators", nargs="*",
                        help="gosterge(ler); '-' verilirse stdin okunur")
    parser.add_argument("-f", "--file", action="append", default=[],
                        help="icinden IOC cikarilacak dosya (tekrarlanabilir)")
    parser.add_argument("--extract-only", action="store_true",
                        help="hicbir sorgu yapma, sadece bulunan IOC'leri yazdir")
    parser.add_argument("--offline", action="store_true",
                        help="cevrimdisi calis (ag istegi yok)")
    parser.add_argument("--free-only", action="store_true",
                        help="sadece API anahtari gerektirmeyen kaynaklari kullan")
    parser.add_argument("--providers", help="virgulle ayrilmis kaynak adlari")
    parser.add_argument("--types", help="sadece bu IOC turlerini isle (orn: ipv4,domain)")
    parser.add_argument("--limit", type=int, default=0, help="en fazla N gosterge islensin")
    parser.add_argument("--workers", type=int, default=4, help="paralel istek sayisi")
    parser.add_argument("--no-cache", action="store_true", help="onbellegi kullanma")
    parser.add_argument("--clear-cache", action="store_true", help="onbellegi temizle ve cik")
    parser.add_argument("--cache-ttl", type=int, default=86400,
                        help="onbellek gecerlilik suresi, saniye (varsayilan 86400)")
    parser.add_argument("--json", metavar="PATH", help="JSON raporu yaz")
    parser.add_argument("--csv", metavar="PATH", help="CSV raporu yaz")
    parser.add_argument("--html", metavar="PATH", help="HTML raporu yaz")
    parser.add_argument("--markdown", metavar="PATH", help="Markdown raporu yaz")
    parser.add_argument("--raw", action="store_true", help="JSON'a ham yanitlari da ekle")
    parser.add_argument("-v", "--verbose", action="store_true", help="hatalari ve linkleri goster")
    parser.add_argument("--no-color", action="store_true", help="ANSI renklerini kapat")
    parser.add_argument("--quiet", action="store_true", help="konsol ciktisini bastir")
    parser.add_argument("--list-providers", action="store_true",
                        help="kaynaklari ve anahtar durumunu listele")
    parser.add_argument("--fail-on", type=int, default=-1, metavar="SKOR",
                        help="bu skor ve uzeri gosterge varsa exit code 1")
    parser.add_argument("-V", "--version", action="version", version=f"iocforge {__version__}")
    return parser


def gather_indicators(args) -> List[Tuple[str, str]]:
    text_blobs: List[str] = []
    direct: List[Tuple[str, str]] = []

    for value in args.indicators:
        if value == "-":
            text_blobs.append(sys.stdin.read())
        elif os.path.isfile(value):
            with open(value, "r", encoding="utf-8", errors="replace") as fh:
                text_blobs.append(fh.read())
        else:
            direct.append((value.strip(), guess_type(value)))

    for path in args.file:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text_blobs.append(fh.read())

    for blob in text_blobs:
        for ioc_type, values in extract(blob).items():
            for value in values:
                direct.append((value, ioc_type))

    seen, out = set(), []
    for value, ioc_type in direct:
        key = value.lower()
        if key not in seen and value:
            seen.add(key)
            out.append((value, ioc_type))
    return out


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    keys = load_keys()

    if args.list_providers:
        print(f"{'KAYNAK':<18}{'ANAHTAR':<22}{'DURUM':<14}DESTEKLENEN TURLER")
        for provider_class in ALL_PROVIDERS:
            has_key = bool(keys.get(provider_class.key_env))
            status = ("hazir" if (not provider_class.requires_key or has_key)
                      else "anahtar yok")
            print(f"{provider_class.name:<18}"
                  f"{(provider_class.key_env or '-'):<22}"
                  f"{status:<14}{', '.join(provider_class.supports)}")
        return 0

    if args.clear_cache:
        cache = Cache(enabled=True)
        cache.clear()
        cache.close()
        print("Onbellek temizlendi.")
        return 0

    if not args.indicators and not args.file:
        build_parser().print_help()
        return 2

    try:
        indicators = gather_indicators(args)
    except OSError as exc:
        print(f"Dosya hatasi: {exc}", file=sys.stderr)
        return 2

    if args.types:
        wanted = {t.strip().lower() for t in args.types.split(",")}
        indicators = [(v, t) for v, t in indicators if t in wanted]
    if args.limit:
        indicators = indicators[:args.limit]

    if not indicators:
        print("Hicbir gosterge bulunamadi.", file=sys.stderr)
        return 2

    if args.extract_only:
        for value, ioc_type in indicators:
            print(f"{ioc_type}\t{value}")
        return 0

    provider_classes = list(ALL_PROVIDERS)
    if args.free_only:
        provider_classes = [p for p in provider_classes if not p.requires_key]
    if args.providers:
        wanted = {n.strip().lower() for n in args.providers.split(",")}
        provider_classes = [p for p in provider_classes if p.name.lower() in wanted]
        if not provider_classes:
            print("Belirtilen kaynak bulunamadi. --list-providers ile bakin.",
                  file=sys.stderr)
            return 2

    cache = Cache(ttl=args.cache_ttl, enabled=not args.no_cache)
    enricher = Enricher(keys=keys, providers=provider_classes, cache=cache,
                        workers=args.workers, offline=args.offline)

    if not args.quiet and enricher.skipped_providers and args.verbose:
        for provider in enricher.skipped_providers:
            print(f"[atlandi] {provider.name}: {provider.key_env} tanimli degil",
                  file=sys.stderr)

    items = enricher.enrich_many(indicators)
    cache.close()

    if not args.quiet:
        print(to_console(items, use_color=not args.no_color, verbose=args.verbose))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(items, include_raw=args.raw))
        print(f"JSON raporu     -> {args.json}")
    if args.csv:
        to_csv(items, args.csv)
        print(f"CSV raporu      -> {args.csv}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(items))
        print(f"HTML raporu     -> {args.html}")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(items))
        print(f"Markdown raporu -> {args.markdown}")

    if args.fail_on >= 0 and any(i.score >= args.fail_on for i in items):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
