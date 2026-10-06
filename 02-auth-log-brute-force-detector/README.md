# Auth Log Brute-Force Detector

A Python script that parses Linux SSH auth logs and produces an incident-style
report: brute-force sources, targeted accounts, account-enumeration attempts,
and — critically — any **successful login from a flagged attacker IP**
(possible compromise).

## Try it

```bash
python3 brute_force_detector.py samples/auth.log
python3 brute_force_detector.py /var/log/auth.log --threshold 10   # your own logs
```

Sample output:

```
TOP SOURCE IPs (failed logins)
  203.0.113.45         14 attempts  <-- BRUTE FORCE
  198.51.100.23         8 attempts  <-- BRUTE FORCE
  192.168.1.21          1 attempts

POSSIBLE COMPROMISES (success after heavy failures)
  !! Oct 6 03:26:41 - 'root' logged in from 203.0.113.45 (flagged brute-force source)
```

The single failed login from `192.168.1.21` (a user typo'ing their password
once) is correctly **not** flagged — the threshold keeps noise out.

## What it detects

- **Brute force**: N+ failed passwords from one IP (configurable threshold)
- **Password spraying**: one account targeted from many different IPs
- **Account enumeration**: repeated `invalid user` attempts reveal username probing
- **Possible compromise**: an `Accepted` login from an IP already flagged

The report ends with concrete remediation steps (firewall block, key-based
auth, fail2ban, MFA, password resets).

## Notes

- Sample data is synthetic and uses TEST-NET documentation IPs
  (`203.0.113.0/24`, `198.51.100.0/24`) — safe to publish, no real
  infrastructure involved.
- Works on real `auth.log` files too; run it against any Linux host you
  administer.

## Skills demonstrated

Log analysis, SSH attack patterns (brute force, spraying, enumeration),
threat detection logic, Python scripting, incident-report writing.
