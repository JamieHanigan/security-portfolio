# Phishing Email Analyzer

A Python tool that scores a raw email (`.eml` file) for phishing indicators
and produces a 0–100 risk report. Built with only the Python standard library —
no dependencies to install.

## What it checks

| Check | Why it matters |
|---|---|
| Envelope (`Return-Path`) vs. `From` mismatch | Spoofed senders often differ from the envelope |
| `Reply-To` mismatch | Replies get routed to the attacker's inbox |
| Display-name brand spoofing | "Chase Online Banking" sent from a lookalike domain |
| Lookalike (typosquat) domains | `chase-secure-verify.com` vs. `chase.com` |
| SPF / DKIM / DMARC failures | Authentication results straight from the headers |
| Urgency / pressure language | "Suspended in 24 hours", "final notice", … |
| Dangerous attachments | `.exe`, `.scr`, `.iso`, `.lnk`, macro-enabled Office docs |
| Link text vs. destination mismatch | Shows `chase.com/...` but links elsewhere |
| URL shorteners | Hide the real destination |

## Try it

```bash
python3 phishing_analyzer.py samples/phishing.eml   # expect HIGH
python3 phishing_analyzer.py samples/legit.eml      # expect LOW
```

Sample output (phishing sample):

```
[+20] Display-name brand spoof
       Display name claims 'Chase Online Banking' but sender domain is 'chase-secure-verify.com'
[+15] SPF failed
       Authentication-Results shows spf=fail
...
RISK SCORE: 100/100  ->  HIGH
```

## Notes

- Detection is **heuristic** — a learning project, not a production mail
  gateway. Real gateways layer reputation, sandboxing, and ML on top of these
  same fundamentals.
- Sample emails are fabricated for demonstration; the phishing sample is
  modeled on common credential-theft lures.

## Skills demonstrated

Email forensics, header analysis (SPF/DKIM/DMARC), social-engineering
indicators, Python scripting, defensive security mindset.
