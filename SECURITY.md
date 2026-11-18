# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability. Use GitHub's private vulnerability reporting on this repository, or email `mohamedait-abbou@users.noreply.github.com` with:

- affected version and OS,
- step-by-step reproduction,
- impact and suggested mitigation.

You should receive an acknowledgement within 72 hours.

## Operational notes

- Live capture requires root/`NET_RAW`. Prefer Linux capabilities (`setcap cap_net_raw,cap_net_admin=eip`) over running the whole process as root.
- Webhook URLs may contain secrets. Keep them in environment variables (`DNS_MONITOR_WEBHOOK_URL`) rather than committed YAML.
- PCAP files and SQLite databases contain internal network metadata. Redact or delete them before attaching to issues.
- The HTML report is self-contained and embeds no remote resources, but it does contain observed domains and IPs — treat it as sensitive.
