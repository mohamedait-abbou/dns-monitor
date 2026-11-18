# Detection rules

Rules are configured under the `detectors:` section. `enabled_rules` is an allow-list: remove an ID from that list to switch the rule off entirely.

```yaml
detectors:
  enabled_rules: [suspicious_keyword, suspicious_tld, high_entropy,
                  long_label, deep_subdomain, txt_tunnel,
                  rate_limit, nxdomain_burst]
  suspicious_keywords: [malware, phishing, botnet, c2, exfil]
  suspicious_tlds: [xyz, top, su, tk, ml]
  entropy_threshold: 3.6
  min_entropy_label_length: 10
  max_label_length: 40
  max_subdomain_depth: 4
  max_txt_answer_length: 120
  rate_threshold: 50
  rate_window: 60
  nxdomain_threshold: 8
  nxdomain_window: 60
  ignore_domains: [in-addr.arpa, ip6.arpa, localhost, local, arpa]
```

## Stateless rules

### `suspicious_keyword` — high

Matches configured substrings in the full domain. Keywords of three characters or fewer must match a whole label, so `c2` does not match `abc2.example.com`.

**Tuning:** keep the list short and specific. Brand names or internal hostnames containing `c2` can produce false positives; add them to `ignore_domains`.

### `suspicious_tld` — medium

Flags domains whose final label is in `suspicious_tlds`. This is intentionally a *weak signal* — combine it with entropy or tunnelling rules for triage.

### `high_entropy` — medium

Computes Shannon entropy per label. Labels shorter than `min_entropy_label_length`, punycode labels and reverse-DNS names are skipped. A 20-character random label scores around 4.0–4.3 bits/char; `www` scores about 1.58.

### `long_label` — medium

Flags any label longer than `max_label_length`. DNS labels are limited to 63 characters, so tunnelling tools often use 40–63 char labels to maximise payload size.

### `deep_subdomain` — low

Flags more than `max_subdomain_depth` labels before the approximated registrable domain. Useful for spotting data encoded into subdomain chains.

### `txt_tunnel` — high

Flags TXT/NULL answers longer than `max_txt_answer_length` bytes. Legitimate SPF/DKIM records can be long; consider allowlisting your own domains if you run mail infrastructure.

## Stateful rules

### `rate_limit` — high

Sliding window of query timestamps per source IP. Alerts when the count reaches `rate_threshold`, then suppresses duplicates for half the window. A resolver, NAT gateway or monitoring probe will legitimately exceed 50 qpm — raise the threshold or run behind a known-resolver allowlist in those environments.

### `nxdomain_burst` — medium

Sliding window of NXDOMAIN responses per source IP. Bursts indicate DGA probing or typo-squatting campaigns. Some scanners and backup software generate steady NXDOMAIN traffic.

## Severity ordering

`info < low < medium < high < critical`. `alerting.min_severity` filters console/webhook delivery but **does not** change what is stored in the report or database.

## False-positive workflow

1. Run with `--simulate 600` to see examples of every rule.
2. Analyse a real capture with `dns-monitor analyze capture.pcap --json out/report.json`.
3. Group triggers with `jq '.alerts_by_rule' out/report.json`.
4. Raise the offending threshold or add the domain/IP to `ignore_domains`.
5. Commit the tuned YAML alongside the deployment configuration.
