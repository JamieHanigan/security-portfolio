#!/usr/bin/env python3
"""
Phishing Email Analyzer
-----------------------
Parses a raw email (.eml) and flags common phishing indicators:
  - Envelope vs. From header mismatch
  - Reply-To mismatch
  - Display-name brand spoofing
  - Lookalike (typosquat) sender domains
  - SPF / DKIM / DMARC authentication failures
  - Urgency / social-engineering language
  - Suspicious attachments
  - Link text vs. link destination mismatches

Usage:
    python phishing_analyzer.py path/to/email.eml

Output: a scored report (0-100) with a LOW / MEDIUM / HIGH verdict.
Sample emails are in the samples/ directory.
"""

import argparse
import difflib
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from urllib.parse import urlparse

# ---------------------------------------------------------------- helpers ---

KNOWN_BRANDS = {
    "paypal.com": ["paypal"],
    "amazon.com": ["amazon"],
    "microsoft.com": ["microsoft", "office365", "outlook", "hotmail"],
    "apple.com": ["apple", "icloud"],
    "google.com": ["google", "gmail"],
    "chase.com": ["chase"],
    "bankofamerica.com": ["bankofamerica"],
    "wellsfargo.com": ["wellsfargo"],
    "netflix.com": ["netflix"],
    "facebook.com": ["facebook"],
    "linkedin.com": ["linkedin"],
    "dhl.com": ["dhl"],
    "ups.com": ["ups"],
    "usps.com": ["usps"],
}

URGENCY_PHRASES = [
    "urgent", "immediately", "suspended", "verify your account",
    "action required", "24 hours", "48 hours", "expire", "locked",
    "unauthorized", "click here", "confirm your identity",
    "security alert", "final notice", "deactivat",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".iso", ".img", ".jar",
    ".msi", ".com", ".pif", ".cpl",
}
MACRO_DOC_EXTENSIONS = {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "rebrand.ly", "cutt.ly",
}


def domain_of(address: str) -> str:
    """Return the domain part of an email address, lowercased."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip("<> ").lower()


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def findings_list():
    return []  # (indicator, detail, points)


# ---------------------------------------------------------------- checks -----

def check_envelope_mismatch(msg, findings):
    """Return-Path (envelope sender) should match the From domain."""
    return_path = (msg.get("Return-Path") or "").strip("<> ")
    from_addrs = getaddresses(msg.get_all("From", []))
    if not return_path or not from_addrs:
        return
    rp_domain = domain_of(return_path)
    from_domain = domain_of(from_addrs[0][1])
    if rp_domain and from_domain and rp_domain != from_domain:
        findings.append((
            "Envelope/From mismatch",
            f"Return-Path domain '{rp_domain}' != From domain '{from_domain}'",
            10,
        ))


def check_reply_to_mismatch(msg, findings):
    """A Reply-To going somewhere other than the sender is suspicious."""
    from_addrs = getaddresses(msg.get_all("From", []))
    reply_addrs = getaddresses(msg.get_all("Reply-To", []))
    if not from_addrs or not reply_addrs:
        return
    from_domain = domain_of(from_addrs[0][1])
    reply_domain = domain_of(reply_addrs[0][1])
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append((
            "Reply-To mismatch",
            f"Replies would go to '{reply_addrs[0][1]}' instead of '{from_domain}'",
            10,
        ))


def check_display_name_spoof(msg, findings):
    """Display name claims a brand, but the address domain doesn't match."""
    from_addrs = getaddresses(msg.get_all("From", []))
    if not from_addrs:
        return
    display_name, address = from_addrs[0]
    from_domain = domain_of(address)
    name_lower = display_name.lower()
    for brand_domain, keywords in KNOWN_BRANDS.items():
        if any(k in name_lower for k in keywords) and from_domain != brand_domain:
            if not from_domain.endswith("." + brand_domain):
                findings.append((
                    "Display-name brand spoof",
                    f"Display name claims '{display_name}' but sender domain is '{from_domain}'",
                    20,
                ))
                return


def check_lookalike_domain(msg, findings):
    """Flag sender domains that closely resemble a known brand's domain."""
    from_addrs = getaddresses(msg.get_all("From", []))
    if not from_addrs:
        return
    from_domain = domain_of(from_addrs[0][1])
    if not from_domain:
        return
    for brand_domain in KNOWN_BRANDS:
        if from_domain == brand_domain or from_domain.endswith("." + brand_domain):
            return  # genuine subdomain or exact match
        ratio = difflib.SequenceMatcher(None, from_domain, brand_domain).ratio()
        if ratio >= 0.75:
            findings.append((
                "Lookalike sender domain",
                f"'{from_domain}' closely resembles '{brand_domain}' (similarity {ratio:.0%})",
                25,
            ))
            return


def check_authentication_results(msg, findings):
    """Parse Authentication-Results for SPF / DKIM / DMARC failures."""
    auth = msg.get("Authentication-Results", "")
    if not auth:
        findings.append((
            "No authentication results",
            "No Authentication-Results header; SPF/DKIM/DMARC status unknown",
            5,
        ))
        return
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}\s*=\s*(\w+)", auth, re.IGNORECASE)
        if match and match.group(1).lower() in ("fail", "softfail", "temperror", "permerror"):
            findings.append((
                f"{mechanism.upper()} failed",
                f"Authentication-Results shows {mechanism}={match.group(1)}",
                15,
            ))


def check_urgency_language(msg, body_text, findings):
    """Score urgency / pressure language in subject and body."""
    text = (msg.get("Subject", "") + "\n" + body_text).lower()
    hits = sorted({phrase for phrase in URGENCY_PHRASES if phrase in text})
    if hits:
        points = min(2 * len(hits), 20)
        findings.append((
            "Urgency / pressure language",
            f"Found: {', '.join(hits)}",
            points,
        ))


def check_attachments(msg, findings):
    """Flag dangerous attachment types (and macro-capable Office docs)."""
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        lower = filename.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in SUSPICIOUS_EXTENSIONS:
            findings.append((
                "Dangerous attachment type",
                f"'{filename}' is commonly used to deliver malware",
                20,
            ))
        elif ext in MACRO_DOC_EXTENSIONS:
            findings.append((
                "Macro-capable document",
                f"'{filename}' can carry malicious macros",
                10,
            ))


def check_links(msg, findings):
    """Flag link-text/href mismatches and URL shorteners in the HTML body."""
    html = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            try:
                html += part.get_content()
            except Exception:
                continue
    if not html:
        return
    link_hits = 0
    for match in re.finditer(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        href, label = match.group(1), re.sub(r"<[^>]+>", "", match.group(2)).strip()
        href_host = host_of(href)
        label_host = host_of("http://" + label) if label and "." in label else ""
        if href_host and label_host and href_host != label_host:
            findings.append((
                "Link text / destination mismatch",
                f"Link shows '{label}' but goes to '{href_host}'",
                15,
            ))
            link_hits += 1
        elif href_host in SHORTENERS:
            findings.append((
                "URL shortener",
                f"Link uses shortener '{href_host}' which hides the real destination",
                10,
            ))
            link_hits += 1
        if link_hits >= 2:
            break


# ---------------------------------------------------------------- main -------

def analyze(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    findings = []
    check_envelope_mismatch(msg, findings)
    check_reply_to_mismatch(msg, findings)
    check_display_name_spoof(msg, findings)
    check_lookalike_domain(msg, findings)
    check_authentication_results(msg, findings)

    body_text = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body_text += part.get_content()
            except Exception:
                continue
    check_urgency_language(msg, body_text, findings)
    check_attachments(msg, findings)
    check_links(msg, findings)

    score = min(sum(f[2] for f in findings), 100)
    verdict = "LOW" if score < 25 else "MEDIUM" if score < 60 else "HIGH"

    from_addrs = getaddresses(msg.get_all("From", []))
    sender = from_addrs[0][1] if from_addrs else "(unknown)"

    lines = [
        "=" * 64,
        "PHISHING ANALYSIS REPORT",
        "=" * 64,
        f"File:    {path}",
        f"From:    {sender}",
        f"Subject: {msg.get('Subject', '(none)')}",
        f"Date:    {msg.get('Date', '(none)')}",
        "-" * 64,
    ]
    if findings:
        for indicator, detail, points in findings:
            lines.append(f"[+{points:>2}] {indicator}\n       {detail}")
    else:
        lines.append("No phishing indicators found.")
    lines += [
        "-" * 64,
        f"RISK SCORE: {score}/100  ->  {verdict}",
        "=" * 64,
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Score a raw .eml file for phishing indicators.")
    parser.add_argument("eml_file", help="Path to the raw email file (.eml)")
    args = parser.parse_args()
    try:
        print(analyze(args.eml_file))
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.eml_file}")


if __name__ == "__main__":
    main()
