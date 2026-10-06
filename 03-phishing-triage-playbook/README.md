# Phishing Triage Playbook

A step-by-step incident-response playbook for triaging reported phishing
emails, written for a small SOC or IT team. Follows the NIST SP 800-61 phases:

1. **Preparation** — reporting channels, roles, triage SLAs
2. **Detection & Analysis** — header/URL/attachment checklist + severity matrix
3. **Containment** — quarantine, blocks, session revocation, host isolation
4. **Eradication** — removing persistence (e.g. malicious inbox rules), re-imaging
5. **Recovery** — returning to service, 30-day monitoring, user notification
6. **Lessons Learned** — metrics and playbook updates

Also included: an IOC tracking table template and references.

→ Read the full playbook: [playbook.md](playbook.md)

Pairs with the [Phishing Email Analyzer](../01-phishing-email-analyzer),
which automates the header checks in Phase 2.

## Skills demonstrated

Incident response process, NIST 800-61 framework, phishing analysis workflow,
documentation, and clear technical writing for a team audience.
