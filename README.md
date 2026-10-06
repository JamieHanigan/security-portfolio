# Security Analyst Portfolio — Jamie Hanigan

Hands-on defensive security projects: phishing analysis, log-based threat
detection, and incident response process. Built while pursuing the CompTIA
Security+ (SY0-701) — I already hold CompTIA A+ and Network+.

## Projects

| # | Project | What it is |
|---|---|---|
| 01 | [Phishing Email Analyzer](01-phishing-email-analyzer) | Python tool that scores a raw `.eml` file for spoofing, auth failures, lookalike domains, urgency language, bad attachments, and link mismatches |
| 02 | [Auth Log Brute-Force Detector](02-auth-log-brute-force-detector) | Python script that parses SSH auth logs to find brute-force attacks, password spraying, account enumeration, and logins from attacker IPs |
| 03 | [Phishing Triage Playbook](03-phishing-triage-playbook) | NIST 800-61-aligned incident response playbook for triaging reported phishing, with severity matrix and IOC tracking template |

## How to run the demos

```bash
cd 01-phishing-email-analyzer
python3 phishing_analyzer.py samples/phishing.eml
python3 phishing_analyzer.py samples/legit.eml

cd ../02-auth-log-brute-force-detector
python3 brute_force_detector.py samples/auth.log
```

Python 3.8+, no dependencies — standard library only.

## Background

- **Certifications:** CompTIA A+, CompTIA Network+, Security+ (SY0-701 in progress)
- **Experience:** document auditing, data entry, technical support, and
  HIPAA-aware handling of sensitive customer/patient data across finance,
  healthcare, and retail
- All sample data in these projects is synthetic and safe to publish.
