# Phishing Triage Playbook

A practical incident-response playbook for triaging reported phishing emails in a
small SOC or IT team. Follows the NIST SP 800-61 phases: Preparation, Detection
& Analysis, Containment, Eradication, Recovery, and Lessons Learned.

> **Related project:** the [Phishing Email Analyzer](../01-phishing-email-analyzer)
> in this portfolio automates the header checks described in Phase 2.

---

## 1. Preparation

- Maintain a monitored phishing inbox (e.g. `phishing@company.com`) and a
  one-click "Report Phish" button in the mail client.
- Keep an allow-list of known-good sender domains and a block-list feed.
- Have tooling ready: an email-header analyzer, a URL detonation sandbox
  (any.run, urlscan.io), and access to the mail gateway quarantine.
- Define the triage SLA: **acknowledge within 30 minutes**, initial verdict
  within 2 hours of a report.

### Roles

| Role | Responsibility |
|---|---|
| Triage analyst | First responder: acknowledges reports, runs header/URL analysis, assigns severity |
| Incident handler | Owns containment and eradication for HIGH-severity cases |
| IT admin | Executes mailbox/mail-flow rule changes, password resets |
| Communications | Drafts user notifications for confirmed campaigns |

## 2. Detection & Analysis

For every reported message, work through this checklist **before** taking action:

1. **Do not click links or open attachments.** Work from the raw message or a
   sandboxed preview.
2. **Inspect headers** (From, Return-Path, Reply-To, Received chain,
   Authentication-Results):
   - Does the envelope sender match the From domain?
   - Do SPF, DKIM, and DMARC all pass? Any single failure is a red flag.
   - Does the display name claim a brand the sending domain doesn't own?
3. **Check links**: hover or extract the real `href`. Flag link-text/href
   mismatches and URL shorteners.
4. **Check attachments**: block-listed extensions (`.exe`, `.scr`, `.iso`,
   `.lnk`, `.hta`, macro-enabled Office docs). Detonate in a sandbox if unsure.
5. **Search the mail gateway**: how many other users received the same
   message ID / sender / subject? A campaign is worse than a single phish.
6. **Check for credential theft**: if the link led to a fake login page,
   pull proxy/firewall logs to see if anyone submitted credentials.

### Severity matrix

| Severity | Criteria | Response |
|---|---|---|
| **LOW** | Single report, no clicks, no auth failures | Log, delete from mailbox, close |
| **MEDIUM** | Multiple recipients, or one user clicked | Quarantine remaining copies, reset clicked user's password, monitor |
| **HIGH** | Credentials submitted, malware executed, or BEC/finance fraud | Full incident: isolate host, force org-wide password reset, engage leadership |

## 3. Containment (short-term)

- Quarantine all remaining copies from mailboxes via the mail gateway.
- Block the sender domain, IPs, and URLs at the email gateway and web proxy.
- If credentials were entered: force a password reset **and** revoke active
  sessions/tokens for the affected accounts.
- If an attachment executed: isolate the endpoint from the network (leave it
  powered on for forensics).

## 4. Eradication

- Remove persistence: delete malicious inbox rules the attacker may have
  created (a classic BEC move is an auto-forward rule).
- Re-image or restore affected endpoints from known-good media.
- Hunt for lateral movement: review logins from the compromised account in
  the 72 hours after the click.

## 5. Recovery

- Return endpoints and accounts to service after validation.
- Monitor the affected accounts and sender infrastructure for 30 days.
- Send a brief, blame-free notification to users who received the campaign:
  what it looked like, what to do if they clicked.

## 6. Lessons Learned (within 5 business days)

- Was the phish caught by a user report or by tooling? If tooling missed it,
  tune the gateway rule.
- Update this playbook and the block-lists with the new IOCs.
- Track metrics: mean time to acknowledge, mean time to quarantine, % of
  users who clicked before containment.

---

## IOC tracking template

| Date | Indicator type | Value | Source | Action taken |
|---|---|---|---|
| 2026-10-05 | sender domain | chase-secure-verify.com | user report | blocked at gateway |
| 2026-10-05 | URL | chase-secure-verify.com/login | header analysis | blocked at proxy |
| 2026-10-05 | reply-to | support@chase-verify-helpdesk.net | header analysis | blocked at gateway |

## References

- NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide
- CISA Phishing Guidance — https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing
