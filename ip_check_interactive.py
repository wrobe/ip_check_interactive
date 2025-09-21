#!/usr/bin/env python3
"""
ip_check_interactive.py

Interactive SOC helper:
- Asks for an IP (IPv4/IPv6)
- VirusTotal: malicious engine count
- AbuseIPDB: reports + confidence score
- IPinfo: city, *country (expanded from ISO code to full name when needed)*
- IP2Proxy: proxy/VPN detection (fallback to IPinfo privacy flags)
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
import random
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
    """
    GET JSON with exponential backoff on 429/5xx, honoring Retry-After, with jitter.
    Returns dict on success, None otherwise.
    """
    delay = 1.5
    base_headers = {
        "User-Agent": "kw-soc-ip-check/1.2 (+https://example.internal)",
        "Accept": "application/json",
    }

    for _ in range(5):
        try:
            h = {**base_headers, **(headers or {})}
            r = requests.get(url, headers=h, params=params or {}, timeout=timeout)
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

        # If it's not retryable, log and stop
        if r.status_code not in RETRY_STATUS:
            snippet = r.text[:200].replace("\n", " ")
            sys.stderr.write(f"[!] {url} -> HTTP {r.status_code}: {snippet}\n")
            return None

        # Retry on 429/5xx; honor Retry-After when present
        sleep_for = delay
        ra = r.headers.get("Retry-After")
        if ra:
            try:
                sleep_for = max(float(ra), delay)
            except ValueError:
                pass
        time.sleep(sleep_for + random.uniform(0, 0.5))
        delay *= 2

    sys.stderr.write(f"[!] {url} -> giving up after retries.\n")
    return None


# ------------ ISO country mapping (alpha-2 -> English name) ------------

COUNTRY_BY_ALPHA2: Dict[str, str] = {
    "AF": "Afghanistan", "AX": "Åland Islands", "AL": "Albania", "DZ": "Algeria",
    "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla",
    "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia",
    "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados",
    "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
    "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia", "BQ": "Bonaire, Sint Eustatius and Saba",
    "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil",
    "IO": "British Indian Ocean Territory", "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso",
    "BI": "Burundi", "CV": "Cabo Verde", "KH": "Cambodia", "CM": "Cameroon",
    "CA": "Canada", "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad",
    "CL": "Chile", "CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands",
    "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "DR Congo",
    "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Côte d’Ivoire", "HR": "Croatia",
    "CU": "Cuba", "CW": "Curaçao", "CY": "Cyprus", "CZ": "Czechia",
    "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic",
    "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
    "ER": "Eritrea", "EE": "Estonia", "SZ": "Eswatini", "ET": "Ethiopia",
    "FK": "Falkland Islands", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland",
    "FR": "France", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French Southern Territories",
    "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland",
    "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala",
    "GG": "Guernsey", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana",
    "HT": "Haiti", "HM": "Heard Island and McDonald Islands", "VA": "Holy See",
    "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland",
    "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel", "IT": "Italy",
    "JM": "Jamaica", "JP": "Japan", "JE": "Jersey", "JO": "Jordan",
    "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos",
    "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
    "MO": "Macao", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia",
    "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte",
    "MX": "Mexico", "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco",
    "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat", "MA": "Morocco",
    "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru",
    "NP": "Nepal", "NL": "Netherlands", "NC": "New Caledonia", "NZ": "New Zealand",
    "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue",
    "NF": "Norfolk Island", "MK": "North Macedonia", "MP": "Northern Mariana Islands", "NO": "Norway",
    "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestine",
    "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru",
    "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal",
    "PR": "Puerto Rico", "QA": "Qatar", "RE": "Réunion", "RO": "Romania",
    "RU": "Russia", "RW": "Rwanda", "BL": "Saint Barthélemy", "SH": "Saint Helena",
    "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "MF": "Saint Martin", "PM": "Saint Pierre and Miquelon",
    "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "São Tomé and Príncipe",
    "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia", "SC": "Seychelles",
    "SL": "Sierra Leone", "SG": "Singapore", "SX": "Sint Maarten", "SK": "Slovakia",
    "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
    "GS": "South Georgia and the South Sandwich Islands", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SE": "Sweden",
    "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan",
    "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo",
    "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia",
    "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu",
    "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
    "US": "United States", "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan",
    "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam", "VG": "British Virgin Islands",
    "VI": "U.S. Virgin Islands", "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen",
    "ZM": "Zambia", "ZW": "Zimbabwe",
    # Non-ISO reserved but commonly seen codes:
    "XK": "Kosovo"
}

def resolve_country_name(country: str) -> str:
    """
    If input is a 2-letter ISO code, return the English country name.
    Otherwise, return input as-is.
    """
    if not country:
        return ""
    c = country.strip()
    if len(c) == 2:
        return COUNTRY_BY_ALPHA2.get(c.upper(), c)
    return c


# ------------ Provider Integrations ------------

def vt_malicious_count(ip: str, api_key: str) -> Optional[int]:
    """
    VirusTotal v3 IP report: https://www.virustotal.com/api/v3/ip_addresses/{ip}
    Reads attributes.last_analysis_stats.malicious (Optional[int]).
    """
    if not api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key, "accept": "application/json"}
    data = http_get_json(url, headers=headers)
    if not data:
        return None
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return int(stats.get("malicious", 0))
    except Exception:
        return None


def abuseipdb_reports_and_score(ip: str, api_key: str, max_age_days: int = 90) -> Tuple[Optional[int], Optional[int]]:
    """
    AbuseIPDB v2 CHECK:
      GET https://api.abuseipdb.com/api/v2/check?ipAddress=...&maxAgeInDays=...&verbose
    Returns (totalReports, abuseConfidenceScore) as Optional[int] values.
    """
    if not api_key:
        return (None, None)
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    # The docs present 'verbose' as a flag; 'true' is widely accepted.
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": "true"}
    data = http_get_json(url, headers=headers, params=params)
    if not data:
        return (None, None)
    try:
        d = data["data"]
        total = int(d.get("totalReports", 0))
        score = int(d.get("abuseConfidenceScore", 0))
        return (total, score)
    except Exception:
        return (None, None)


def ipinfo_lookup(ip: str, token: str) -> Tuple[str, str, Dict[str, Any]]:
    """
    IPinfo:
      1) Try Plus 'lookup' endpoint (new schema with 'geo' + privacy fields).
      2) If not entitled (403) or fails, fall back to legacy endpoint.
    Returns (city, country, raw_json).
    """
    if not token:
        return ("", "", {})

    # Try Plus API first
    url_plus = f"https://api.ipinfo.io/lookup/{ip}"
    data = http_get_json(url_plus, params={"token": token})

    # Fallback to legacy/standard endpoint if Plus is unavailable
    if not data:
        url_std = f"https://ipinfo.io/{ip}"
        data = http_get_json(url_std, params={"token": token}) or {}

    # Extract city/country from either Plus 'geo' object or legacy flat fields
    city = ""
    country = ""
    try:
        geo = data.get("geo", {}) if isinstance(data, dict) else {}
        if isinstance(geo, dict):
            city = geo.get("city", "") or data.get("city", "")
            country = geo.get("country", "") or data.get("country", "")
        else:
            city = data.get("city", "")
            country = data.get("country", "")
    except Exception:
        pass

    return (city or "", country or "", data)


def ip2proxy_check(ip: str, api_key: str) -> Tuple[bool, str, str, bool]:
    """
    IP2Proxy Web Service (PX11 JSON):
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
    If IP2Proxy is unavailable, use IPinfo privacy flags when present:
      - Treat any of {vpn, proxy, tor, relay} as anonymous.
      - proxy_type reflects the first positive signal; provider populated if available.
    """
    anon = ipinfo_json.get("anonymous", {}) or {}
    flags = {
        "VPN": bool(anon.get("is_vpn")),
        "Proxy": bool(anon.get("is_proxy")),
        "Tor": bool(anon.get("is_tor")),
        "Relay": bool(anon.get("is_relay")),
    }
    is_anon = any(flags.values()) or bool(ipinfo_json.get("is_anonymous"))
    proxy_type = next((k for k, v in flags.items() if v), "Anonymous IP") if is_anon else ""
    provider = (anon.get("name") or "").strip()
    return (is_anon, proxy_type, provider)


# ------------ Formatting ------------

def final_sentence(ip: str,
                   city: str,
                   country: str,
                   vt_count: Optional[int],
                   abuse_total: Optional[int],
                   abuse_score: Optional[int],
                   is_proxy: Optional[bool],
                   proxy_type: str,
                   provider: str) -> str:
    """
    Compose a single line. If a source wasn't checked, avoid implying "clean".
    """
    location = f"{city}, {country}".strip(", ")
    location = location or "-"

    if vt_count is None:
        vt_phrase = "was not checked"
    else:
        vt_phrase = "has" if vt_count > 0 else "has not"

    if abuse_total is None or abuse_score is None:
        abuse_phrase = "was not checked"
    else:
        abuse_phrase = "has" if (abuse_total > 0 or abuse_score > 0) else "has not"

    if is_proxy is None:
        proxy_phrase = "could not determine if it belongs to"
    else:
        proxy_phrase = "belongs to" if is_proxy else "does not belong to"

    extra = ""
    if is_proxy and (proxy_type or provider):
        details = ", ".join([v for v in [proxy_type, provider] if v])
        extra = f" ({details})"

    return (f"IP {ip} mapped to {location} "
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
    city, country_raw, ipinfo_raw = ipinfo_lookup(ip, ipinfo_token)
    country = resolve_country_name(country_raw)

    vt_count = vt_malicious_count(ip, vt_key)                  # Optional[int]
    abuse_total, abuse_score = abuseipdb_reports_and_score(ip, abuse_key)  # Optional[int], Optional[int]

    # IP2Proxy or fallback
    is_proxy: Optional[bool] = None
    proxy_type = ""
    provider = ""
    used_ip2proxy = False

    if ip2proxy_key:
        is_proxy_val, proxy_type, provider, used_ip2proxy = ip2proxy_check(ip, ip2proxy_key)
        if used_ip2proxy:
            is_proxy = is_proxy_val

    if not used_ip2proxy:
        # Fallback via IPinfo privacy flags, but only if we have IPinfo data
        if ipinfo_raw:
            is_proxy_val, proxy_type, provider = proxy_fallback_from_ipinfo(ipinfo_raw)
            is_proxy = is_proxy_val
        else:
            # Could not determine proxy status at all
            is_proxy = None
            proxy_type = ""
            provider = ""

    # Final sentence
    sentence = final_sentence(ip, city, country,
                              vt_count, abuse_total, abuse_score,
                              is_proxy, proxy_type, provider)

    # Output helper
    def fmt(x: Optional[int], reason: str) -> str:
        return str(x) if x is not None else f"skipped ({reason})"

    # Output
    print("\n" + "=" * 80)
    print(sentence)
    print("-" * 80)
    print(f"• VirusTotal malicious detections: {fmt(vt_count, 'no VT_API_KEY or error')}")
    print("• AbuseIPDB reports (last 90 days): "
          f"{fmt(abuse_total, 'no ABUSEIPDB_API_KEY or error')}  | "
          f"confidence score: {abuse_score if abuse_score is not None else '-'}")
    print(f"• Location (IPinfo): City='{city or '-'}', Country='{country or '-'}'")

    if used_ip2proxy:
        print(f"• Proxy/VPN (IP2Proxy): {'YES' if is_proxy else 'NO'}"
              f"{' | type=' + proxy_type if proxy_type else ''}"
              f"{' | provider=' + provider if provider else ''}")
    else:
        if not ipinfo_raw:
            print("• Proxy/VPN (fallback): skipped (IPinfo unavailable)")
        else:
            print(f"• Proxy/VPN (fallback via IPinfo privacy): "
                  f"{'YES' if is_proxy else 'NO'}"
                  f"{' | type=' + proxy_type if proxy_type else ''}"
                  f"{' | provider=' + provider if provider else ''}")
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
