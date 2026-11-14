#!/usr/bin/env python3
"""phishcheck - rule-based phishing URL risk scorer.

Original code. Rule ideas inspired by common phishing heuristics
(IP hosts, punycode, @-tricks, lookalike keywords). No external deps.
"""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "icu"}
KEYWORDS = ("login", "verify", "verification", "secure", "security", "account",
            "update", "confirm", "banking", "signin", "password", "wallet",
            "support", "billing", "invoice", "upi", "paytm", "phonepe", "gpay")
BRANDS = ("google", "facebook", "instagram", "amazon", "apple", "microsoft",
          "paypal", "netflix", "hdfc", "sbi", "icici", "axis")

def _host_of(url):
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    return p, (p.hostname or "")

def analyze(url):
    """Return dict(score 0-100, verdict, findings[list of (points, reason)])."""
    findings = []
    p, host = _host_of(url)
    if not host:
        return {"url": url, "score": 100, "verdict": "high risk",
                "findings": [(100, "could not parse a host from this URL")]}

    def add(points, reason):
        findings.append((points, reason))

    if p.scheme == "http":
        add(10, "plain http, no TLS")
    if "@" in p.netloc:
        add(30, "contains @ - the real host is after it, a classic redirect trick")
    try:
        ipaddress.ip_address(host)
        add(30, "host is a raw IP address, not a domain")
    except ValueError:
        pass
    if "xn--" in host:
        add(25, "punycode (xn--) in host - can hide lookalike characters")
    if any(ord(c) > 127 for c in host):
        add(15, "non-ASCII characters in host")
    labels = host.split(".")
    if len(labels) > 3:
        add(15, f"{len(labels) - 2} subdomains - long chains hide the real domain")
    tld = labels[-1].lower()
    if tld in RISKY_TLDS:
        add(15, f".{tld} is a heavily abused TLD")
    base = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if base in SHORTENERS:
        add(20, "URL shortener - final destination is hidden")
    if host.count("-") >= 3:
        add(10, "many hyphens in host")
    if re.search(r"\d{4,}", host):
        add(10, "long digit run in host")
    text = (host + p.path).lower()
    hits = [k for k in KEYWORDS if k in text]
    if hits:
        add(5 + 5 * len(hits), "sensitive keywords: " + ", ".join(sorted(set(hits))))
    for brand in BRANDS:
        if brand in host and not host.endswith(brand + ".com"):
            add(25, f"mentions '{brand}' but is not {brand}.com - possible lookalike")
            break
    if len(p.path) > 60:
        add(5, "very long path")
    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", p.query):
        add(10, "base64-looking blob in query string")

    score = min(100, sum(pts for pts, _ in findings))
    verdict = "high risk" if score >= 50 else "suspicious" if score >= 25 else "low risk"
    return {"url": url, "score": score, "verdict": verdict, "findings": findings}

def main(argv=None):
    ap = argparse.ArgumentParser(description="Rule-based phishing URL risk scorer")
    ap.add_argument("urls", nargs="*", help="URLs to check")
    ap.add_argument("--file", help="file with one URL per line")
    ap.add_argument("--json", action="store_true", help="JSON output")
    a = ap.parse_args(argv)
    urls = list(a.urls)
    if a.file:
        urls += [l.strip() for l in open(a.file, encoding="utf-8") if l.strip()]
    if not urls:
        ap.error("give at least one URL or --file")
    results = [analyze(u) for u in urls]
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"\n{r['url']}\n  score {r['score']}/100 - {r['verdict'].upper()}")
            for pts, why in r["findings"]:
                print(f"  +{pts:>3}  {why}")
            if not r["findings"]:
                print("       no warning signs found by these rules")
    return 1 if any(r["score"] >= 50 for r in results) else 0

if __name__ == "__main__":
    sys.exit(main())
