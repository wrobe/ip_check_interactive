# ip_check_interactive

An interactive SOC helper script to enrich a single IPv4/IPv6 address using threat intelligence and IP reputation sources.

---

## Features
- **VirusTotal**: malicious engine count
- **AbuseIPDB**: reports and confidence score
- **IPinfo**: city and country (ISO code mapped to full name)
- **IP2Proxy**: proxy/VPN detection (fallback to IPinfo privacy flags)
- Graceful fallback from IPinfo Plus to legacy endpoint
- Clear output distinguishing skipped vs clean results
- Retry-After support and jitter for HTTP resilience

---

## Requirements
- Python 3.9+
- Packages: `requests`, `python-dotenv`

Install dependencies:
```bash
pip install requests python-dotenv
