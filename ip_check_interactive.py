#!/usr/bin/env python3
"""
ip_check_interactive.py

Interactive SOC helper:
- Asks for an IP (IPv4/IPv6)
- VirusTotal: malicious engine count
- AbuseIPDB: reports + confidence score
- IPinfo: city, country (and anonymity flags for fallback)
- IP2Proxy: proxy/VPN detection (uses IPinfo anonymity as fallback)
- Prints your requested one-line sentence + a short breakdown

Setup:
  pip install requests python-dotenv
  (Optionally create a .env with VT_API_KEY, ABUSEIPDB_API_KEY, IPINFO_TOKEN, IP2PROXY_API_KEY)

Author: Krzysztof Wróbel 
"""

from __future__ import annotations
import os
import sys
import time
import ipaddress
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

try:
    from dotenv import load_dotenv  # type: ignore
    # Always load the .env file that sits next to this script
    env_path = Path(__file__).with_name(".env")
    load_dotenv(dotenv_path=env_path, override=True)
except Exception:
    pass  # Script will still work if dotenv isn't installed


import requests


# ------------ Configuration / Runtime Helpers ------------

TIMEOUT = 15
RETRY_STATUS = {429, 500, 502, 503, 504}

def getenv_or_prompt(name: str, prompt_text: str) -> str:
    val = os.getenv(name, "").strip()
    if val:
        return val
    try:
        # Prompt only in interactive terminals
        if sys.stdin.isatty():
            return input(prompt_text).strip()
    except Exception:
        pass
    return ""


def http_get_json(url: str,
                  headers: Optional[Dict[str, str]] = None,
                  params: Optional[Dict[str, Any]] = None,
                  timeout: int = TIMEOUT) -> Optional[dict]:
    """GET JSON with simple exponential backoff on rate-limit/server errors."""
    delay = 1.5
    for _ in range(5):
        try:
            r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        except requests.RequestException as e:
            sys.stderr.write(f"[!] HTTP error calling {url}: {e}\n")
            time.sleep(delay)
            delay *= 2
            continue

        if r.status_code < 400:
            try:
                return r.json()
            except Exception:
                sys.stderr.write(f"[!] Non-JSON response from {url}\n")
                return None

        if r.status_code not in RETRY_STATUS:
            sys.stderr.write(f"[!] {url} -> HTTP {r.status_code}: {r.text[:200]}\n")
            return None

        # Retry on 429/5xx
        time.sleep(delay)
        delay *= 2

    sys.stderr.write(f"[!] {url} -> giving up after retries.\n")
    return None


# ------------ Provider Integrations ------------

def vt_malicious_count(ip: str, api_key: str) -> int:
    """
    VirusTotal v3 IP report: https://www.virustotal.com/api/v3/ip_addresses/{ip}
    We read attributes.last_analysis_stats.malicious
    """
    if not api_key:
        return 0
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    data = http_get_json(url, headers=headers)
    if not data:
        return 0
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return int(stats.get("malicious", 0))
    except Exception:
        return 0


def abuseipdb_reports_and_score(ip: str, api_key: str, max_age_days: int = 90) -> Tuple[int, int]:
    """
    AbuseIPDB v2 CHECK endpoint:
    GET https://api.abuseipdb.com/api/v2/check?ipAddress=...&maxAgeInDays=90&verbose
    Returns (totalReports, abuseConfidenceScore)
    """
    if not api_key:
        return (0, 0)
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": ""}
    data = http_get_json(url, headers=headers, params=params)
    if not data:
        return (0, 0)
    try:
        d = data["data"]
        total = int(d.get("totalReports", 0))
        score = int(d.get("abuseConfidenceScore", 0))
        return (total, score)
    except Exception:
        return (0, 0)


def ipinfo_lookup(ip: str, token: str) -> Tuple[str, str, Dict[str, Any]]:
    """
    IPinfo Core lookup:
      - Preferred (new) schema: {"geo": {"city": "...", "country": "..."}, ...}
      - Fallback to legacy flat fields if needed.
    Returns (city, country, raw_json_for_flags)
    """
    if not token:
        return ("", "", {})
    url = f"https://api.ipinfo.io/lookup/{ip}"
    params = {"token": token}
    data = http_get_json(url, params=params) or {}
    city = ""
    country = ""
    try:
        geo = data.get("geo", {})
        city = geo.get("city", "") or data.get("city", "")
        country = geo.get("country", "") or data.get("country", "")
    except Exception:
        pass
    return (city or "", country or "", data)


def ip2proxy_check(ip: str, api_key: str) -> Tuple[bool, str, str, bool]:
    """
    IP2Proxy Web Service:
      https://api.ip2proxy.com/?key=...&ip=...&package=PX11&format=json
    Returns (is_proxy, proxy_type, provider, used_ip2proxy)
    """
    if not api_key:
        return (False, "", "", False)

    url = "https://api.ip2proxy.com/"
    params = {"key": api_key, "ip": ip, "package": "PX11", "format": "json"}
    data = http_get_json(url, params=params)
    if not data:
        return (False, "", "", False)

    raw = str(data.get("isProxy", "")).strip().lower()
    is_proxy = raw in {"1", "y", "yes", "true", "t"}
    proxy_type = (data.get("proxyType") or "").strip()
    provider = (data.get("provider") or "").strip()
    return (is_proxy, proxy_type, provider, True)


def proxy_fallback_from_ipinfo(ipinfo_json: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    If IP2Proxy is unavailable, use IPinfo flags:
      - Treat is_anonymous=True as proxy/vpn
      - We won’t have a provider; proxy_type set to 'Anonymous IP'
    """
    is_anon = bool(ipinfo_json.get("is_anonymous"))
    proxy_type = "Anonymous IP" if is_anon else ""
    provider = ""
    return (is_anon, proxy_type, provider)


# ------------ Formatting ------------

def final_sentence(ip: str,
                   city: str,
                   country: str,
                   vt_count: int,
                   abuse_total: int,
                   abuse_score: int,
                   is_proxy: bool,
                   proxy_type: str,
                   provider: str) -> str:
    """
    Compose:
    IP {IP} mapped {City Country} has/has not malicious reports from VirusTotal and {has/has not} malicious reports
    from AbuseIPDB and belongs/does not belong to proxy/vpn provider (type/provider).
    """
    location = f"{city}, {country}".strip(", ")
    vt_phrase = "has" if vt_count > 0 else "has not"
    abuse_phrase = "has" if (abuse_total > 0 or abuse_score > 0) else "has not"
    proxy_phrase = "belongs to" if is_proxy else "does not belong to"

    extra = ""
    if is_proxy and (proxy_type or provider):
        details = ", ".join([v for v in [proxy_type, provider] if v])
        extra = f" ({details})"

    return (f"IP {ip} mapped {location} "
            f"{vt_phrase} malicious reports from VirusTotal and "
            f"{abuse_phrase} malicious reports from AbuseIPDB and "
            f"{proxy_phrase} proxy/vpn provider{extra}")


# ------------ Main Flow ------------

def process_ip(ip: str,
               vt_key: str,
               abuse_key: str,
               ipinfo_token: str,
               ip2proxy_key: str) -> None:
    # Validate IP
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private:
            sys.stderr.write(f"[!] {ip} is a private/reserved IP; external intel may be limited.\n")
    except ValueError:
        print(f"[X] '{ip}' is not a valid IP address.")
        return

    # Lookups
    city, country, ipinfo_raw = ipinfo_lookup(ip, ipinfo_token)
    vt_count = vt_malicious_count(ip, vt_key)
    abuse_total, abuse_score = abuseipdb_reports_and_score(ip, abuse_key)

    # IP2Proxy or fallback
    is_proxy = False
    proxy_type = ""
    provider = ""
    used_ip2proxy = False

    if ip2proxy_key:
        is_proxy, proxy_type, provider, used_ip2proxy = ip2proxy_check(ip, ip2proxy_key)

    if not used_ip2proxy:
        # Fallback via IPinfo anonymity flag
        is_proxy, proxy_type, provider = proxy_fallback_from_ipinfo(ipinfo_raw)

    # Final sentence
    sentence = final_sentence(ip, city, country,
                              vt_count, abuse_total, abuse_score,
                              is_proxy, proxy_type, provider)

    # Output
    print("\n" + "=" * 80)
    print(sentence)
    print("-" * 80)
    print(f"• VirusTotal malicious detections: {vt_count}")
    print(f"• AbuseIPDB reports (last 90 days): {abuse_total}  | confidence score: {abuse_score}")
    print(f"• Location (IPinfo): City='{city or '-'}', Country='{country or '-'}'")
    if used_ip2proxy:
        print(f"• Proxy/VPN (IP2Proxy): {'YES' if is_proxy else 'NO'}"
              f"{' | type=' + proxy_type if proxy_type else ''}"
              f"{' | provider=' + provider if provider else ''}")
    else:
        print(f"• Proxy/VPN (fallback via IPinfo is_anonymous): {'YES' if is_proxy else 'NO'}")
    print("=" * 80 + "\n")


def main() -> None:
    # Gather credentials from env or prompt
    vt_key = getenv_or_prompt("VT_API_KEY", "Enter VirusTotal API key (or leave blank to skip VT): ")
    abuse_key = getenv_or_prompt("ABUSEIPDB_API_KEY", "Enter AbuseIPDB API key (or leave blank to skip AbuseIPDB): ")
    ipinfo_token = getenv_or_prompt("IPINFO_TOKEN", "Enter IPinfo token (required for geolocation & fallback): ")
    ip2proxy_key = getenv_or_prompt("IP2PROXY_API_KEY", "Enter IP2Proxy API key (optional; press Enter to skip): ")

    if not ipinfo_token:
        print("[X] IPinfo token is required. Set IPINFO_TOKEN in your environment or .env, or paste it when prompted.")
        sys.exit(1)

    # Prompt for IP
    try:
        ip = input("Enter IP address (IPv4 or IPv6): ").strip()
    except KeyboardInterrupt:
        print("\nAborted.")
        return

    if not ip:
        print("[X] No IP provided.")
        return

    process_ip(ip, vt_key, abuse_key, ipinfo_token, ip2proxy_key)


if __name__ == "__main__":
    main()
