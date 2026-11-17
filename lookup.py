#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBER OSINT X — ULTIMATE  (Keyless Edition)
IP intelligence & public information lookup tool.
No API keys, no tokens, no registration required.

Platforms : Android (Termux / Pydroid 3), Linux, Windows

KEYLESS DATA SOURCES (all free, no account needed):
  - ip-api.com     : IP geolocation / ISP / ASN   (~45 req/min, HTTP only on free tier)
  - ipwho.is       : IP geolocation fallback      (HTTPS, unlimited fair use)
  - rdap.org       : WHOIS-equivalent domain/ASN  (standard protocol)
  - Google DNS 8.8.8.8 / Cloudflare 1.1.1.1      (DNS records)
  - Live TLS handshake                             (SSL certificate)
  - phonenumbers lib (Google libphonenumber data)  (phone numbering plans)

LIMITATIONS (honest):
  - IP geolocation is APPROXIMATE (city/network level). It is NOT the
    device's actual location and may point to an ISP gateway.
  - Phone module uses public numbering-plan data only. It never
    identifies private subscribers or live locations.
"""

import os
import sys
import re
import socket
import ssl
import time
import ipaddress
import datetime
import platform
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests.  Install with: pip install requests")
    sys.exit(1)

try:
    import phonenumbers
    from phonenumbers import carrier, timezone as pn_tz, geocoder
    HAS_PHONE = True
except ImportError:
    HAS_PHONE = False

# ------------------------------------------------------------------ #
#  CONFIGURATION  (no keys, no tokens — 100% keyless)
# ------------------------------------------------------------------ #

TIMEOUT = 15
RETRIES = 3
RETRY_DELAY = 2
REPORT_DIR = "reports"
USER_AGENT = "CyberOSINTX/1.0 (+public-keyless-lookup-tool)"

# ------------------------------------------------------------------ #
#  TERMINAL UI
# ------------------------------------------------------------------ #

class C:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"

def supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if platform.system() == "Windows":
        return os.environ.get("WT_SESSION") or os.environ.get("ANSICON") \
            or "TERM" in os.environ
    return sys.stdout.isatty()

COLOR = supports_color()

def paint(txt, col):
    return f"{col}{txt}{C.RESET}" if COLOR else txt

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def banner():
    print(paint(r"""
  ____ _        _          ____  ___  ____  __  __ ___ _   _
 / ___| |      / \        / ___|/ _ \|  _ \|  \/  |_ _| \ | |
| |   | |     / _ \ _____| |  _| | | | |_) | |\/| || ||  \| |
| |___| |___ / ___ \_____| |_| | |_| |  _ <| |  | || || |\  |
 \____|_____/_/   \_\     \____|\___/|_| \_\_|  |_|___|_| \_|
     U L T I M A T E  --  KEYLESS  OSINT  LOOKUP  SUITE
""", C.RED))

def loading(msg="Initializing", spins=14):
    chars = "|/-\\"
    for i in range(spins):
        sys.stdout.write("\r  " + paint(f"[{chars[i % 4]}] {msg}...", C.YELLOW))
        sys.stdout.flush()
        time.sleep(0.08)
    sys.stdout.write("\r" + " " * (len(msg) + 22) + "\r")

def progress(label, steps=20, delay=0.03):
    for i in range(steps + 1):
        pct = int(i / steps * 100)
        bar = "#" * i + "-" * (steps - i)
        sys.stdout.write("\r  " + paint(f"[{bar}] {pct}%  {label}", C.GREEN))
        sys.stdout.flush()
        time.sleep(delay)
    print()

def pause():
    input(paint("\n  Press ENTER to continue...", C.CYAN))

def box(title, lines):
    plain = [re.sub(r"\033\[[0-9;]*m", "", l) for l in lines]
    w = max([len(l) for l in plain] + [len(title)]) + 4
    print(paint("  ┌" + "─" * (w + 2) + "┐", C.CYAN))
    print("  │ " + paint(title.ljust(w), C.BOLD) + " │")
    print(paint("  ├" + "─" * (w + 2) + "┤", C.CYAN))
    for l in lines:
        print(f"  │ {l.ljust(w)} │")
    print(paint("  └" + "─" * (w + 2) + "┘", C.CYAN))

def fmt(v):
    if v is None or v == "" or v in ("None", "N/A"):
        return paint("[UNAVAILABLE]", C.YELLOW)
    return str(v)

# ------------------------------------------------------------------ #
#  NETWORK LAYER (timeout + retry)
# ------------------------------------------------------------------ #

def http_get(url, params=None):
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.get(url, params=params, headers={"User-Agent": USER_AGENT},
                             timeout=TIMEOUT)
            if r.status_code == 200:
                return r
            last_err = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            last_err = str(e)[:80]
        time.sleep(RETRY_DELAY * attempt)
    raise RuntimeError(f"request failed after {RETRIES} attempts: {last_err}")

def http_get_json(url, params=None):
    r = http_get(url, params)
    try:
        return r.json()
    except ValueError:
        raise RuntimeError("invalid JSON from API")

# ------------------------------------------------------------------ #
#  IP VALIDATION
# ------------------------------------------------------------------ #

def validate_ip(raw):
    raw = (raw or "").strip()
    if not raw:
        return None, "empty input"
    try:
        return ipaddress.ip_address(raw), None
    except ValueError:
        return None, "not a valid IPv4 or IPv6 address"

def classify_ip(ip):
    if ip.is_private:     return "PRIVATE"
    if ip.is_loopback:    return "LOOPBACK"
    if ip.is_link_local:  return "LINK-LOCAL"
    if ip.is_multicast:   return "MULTICAST"
    if ip.is_reserved:    return "RESERVED"
    return "PUBLIC"

def reverse_dns(ip_str):
    try:
        return socket.gethostbyaddr(ip_str)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None

def detect_my_ip():
    for url in ("https://api.ipify.org?format=json",
                "https://api64.ipify.org?format=json",
                "https://ipwho.is/"):
        try:
            data = http_get_json(url)
            ip = data.get("ip") if isinstance(data, dict) else None
            if ip:
                return ip, url.split("//")[1].split("/")[0]
        except Exception:
            continue
    raise RuntimeError("could not detect public IP (network issue?)")

# ------------------------------------------------------------------ #
#  IP INTELLIGENCE  (keyless only)
# ------------------------------------------------------------------ #

def lookup_ip_api(ip):
    """ip-api.com — free, no key. Note: HTTPS requires a paid key,
    so free tier uses HTTP (fine for public data)."""
    field = ("status,message,country,countryCode,region,regionName,city,"
             "zip,lat,lon,timezone,isp,org,as,asname,reverse,query")
    data = http_get_json(f"http://ip-api.com/json/{ip}", {"fields": field})
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "lookup failed"))
    return {
        "Source":       "ip-api.com (keyless)",
        "IP":           data.get("query"),
        "Country":      data.get("country"),
        "Country code": data.get("countryCode"),
        "Region":       data.get("regionName"),
        "City":         data.get("city"),
        "ZIP":          data.get("zip"),
        "Latitude":     data.get("lat"),
        "Longitude":    data.get("lon"),
        "Timezone":     data.get("timezone"),
        "ISP":          data.get("isp"),
        "Organization": data.get("org"),
        "ASN":          data.get("as"),
        "AS name":      data.get("asname"),
        "Reverse DNS":  data.get("reverse") or reverse_dns(ip),
        "Type":         f"IPv{ipaddress.ip_address(ip).version}",
    }

def lookup_ip_ipwhois(ip):
    """ipwho.is — free, no key, HTTPS."""
    data = http_get_json(f"https://ipwho.is/{ip}")
    if data.get("success") is False:
        raise RuntimeError(data.get("message", "lookup failed"))
    conn = data.get("connection") or {}
    tz = data.get("timezone") or {}
    return {
        "Source":       "ipwho.is (keyless)",
        "IP":           data.get("ip"),
        "Country":      data.get("country"),
        "Country code": data.get("country_code"),
        "Region":       data.get("region"),
        "City":         data.get("city"),
        "ZIP":          data.get("postal"),
        "Latitude":     data.get("latitude"),
        "Longitude":    data.get("longitude"),
        "Timezone":     tz.get("id"),
        "ISP":          conn.get("isp"),
        "Organization": conn.get("org"),
        "ASN":          (f"AS{conn.get('asn')} {conn.get('domain') or ''}".strip()
                         if conn.get("asn") else None),
        "AS name":      conn.get("domain"),
        "Reverse DNS":  reverse_dns(ip),
        "Type":         f"IPv{ipaddress.ip_address(ip).version}",
    }

def lookup_ip(ip, silent=False):
    errors = []
    for fn in (lookup_ip_api, lookup_ip_ipwhois):
        try:
            result = fn(ip)
            if not silent:
                progress("Querying " + result["Source"])
            return result
        except Exception as e:
            errors.append(f"{fn.__name__}: {e}")
    raise RuntimeError("all IP sources failed → " + " | ".join(errors))

# ------------------------------------------------------------------ #
#  PHONE MODULE (public numbering-plan data only)
# ------------------------------------------------------------------ #

def phone_validate(raw):
    if not HAS_PHONE:
        raise RuntimeError("phonenumbers library not installed (pip install phonenumbers)")
    raw = raw.strip()
    if not raw.startswith("+"):
        raw = "+" + raw.lstrip("+0")
    try:
        num = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        raise RuntimeError(f"parse error: {e}")
    if not phonenumbers.is_possible_number(num):
        return {"lines": [f"Input: {raw}",
                          "Status: NOT POSSIBLE (numbering-plan mismatch)",
                          "Note: subscriber identity & live location are NOT looked up."],
                "valid": False}
    valid = phonenumbers.is_valid_number(num)
    region = phonenumbers.region_code_for_number(num)
    cc = phonenumbers.country_code_for_region(region) if region else None
    type_names = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_OR_MOBILE",
                  3: "PREMIUM_RATE", 4: "TOLL_FREE", 5: "SHARED_COST",
                  6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
                  9: "UAN", 10: "VOICEMAIL"}
    numtype = phonenumbers.number_type(num)
    lines = [
        f"Input: {raw}",
        f"Status: {'VALID' if valid else 'POSSIBLE but NOT VALID for this plan'}",
        f"Possible: {phonenumbers.is_possible_number(num)}",
        f"Country: {fmt(region)}",
        f"Country calling code: +{cc}" if cc else "Country calling code: [UNAVAILABLE]",
        f"International format: {fmt(phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL))}",
        f"National format: {fmt(phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL))}",
        f"E.164 format: {fmt(phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164))}",
        f"Number type: {type_names.get(numtype, 'UNKNOWN')}",
    ]
    if valid:
        lines.append(f"Numbering area (approx): {fmt(geocoder.description_for_number(num, 'en'))}")
        lines.append(f"Timezone(s): {fmt(', '.join(pn_tz.time_zones_for_number(num)))}")
        lines.append(f"Carrier (public plan data): {fmt(carrier.name_for_number(num, 'en'))}")
    lines.append("Note: subscriber identity & live location are NOT looked up.")
    return {"lines": lines, "valid": valid}

def phone_country_info(q):
    if not HAS_PHONE:
        raise RuntimeError("phonenumbers library not installed")
    q = q.strip().upper().lstrip("+")
    if q.isdigit():
        regions = list(phonenumbers.region_codes_for_country_code(int(q)))
        if not regions:
            raise RuntimeError(f"no countries use calling code +{q}")
        lines = [f"Calling code: +{q}", f"Countries: {', '.join(regions)}"]
        ex = phonenumbers.example_number_for_type(regions[0], phonenumbers.PhoneNumberType.MOBILE)
        lines.append(f"Example mobile ({regions[0]}): "
                     f"{phonenumbers.format_number(ex, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if ex else '[UNAVAILABLE]'}")
    else:
        if not phonenumbers.is_valid_region_code(q):
            raise RuntimeError(f"unknown region code: {q}")
        cc = phonenumbers.country_code_for_region(q)
        ex = phonenumbers.example_number(q)
        mob = phonenumbers.example_number_for_type(q, phonenumbers.PhoneNumberType.MOBILE)
        f = lambda n: phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if n else "[UNAVAILABLE]"
        lines = [f"Region: {q}", f"Calling code: +{cc}",
                 f"Example (general): {f(ex)}", f"Example (mobile): {f(mob)}"]
    return {"lines": lines}

# ------------------------------------------------------------------ #
#  PUBLIC INFORMATION MODULE
# ------------------------------------------------------------------ #

def dns_lookup(domain, full=True):
    rts = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA") if full else ("A", "AAAA")
    lines = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.lifetime = TIMEOUT
        for rt in rts:
            try:
                ans = resolver.resolve(domain, rt)
                lines.append(f"{rt}: {'; '.join(str(r) for r in ans)}")
            except Exception:
                lines.append(f"{rt}: [UNAVAILABLE]")
    except ImportError:
        for rt, fam in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            try:
                infos = socket.getaddrinfo(domain, None, fam)
                lines.append(f"{rt}: {', '.join(sorted({i[4][0] for i in infos}))}")
            except socket.gaierror:
                lines.append(f"{rt}: [UNAVAILABLE]")
        for extra in ("MX", "NS", "TXT", "CNAME", "SOA"):
            lines.append(f"{extra}: [install 'dnspython' for full records]")
    return lines

def rdap_lookup(domain):
    data = http_get_json(f"https://rdap.org/domain/{domain}")
    lines = [f"Domain: {fmt(data.get('name') or data.get('ldhName'))}"]
    for ev in data.get("events", []):
        lines.append(f"{ev.get('eventAction')}: {ev.get('eventDate')}")
    for ent in data.get("entities", []):
        roles = ", ".join(ent.get("roles", []))
        v = (ent.get("vcardArray") or [None, []])[1]
        fn = next((x[3] for x in v if x[0] == "fn"), None)
        if roles:
            lines.append(f"Entity: {fmt(fn)} ({roles})")
    ns = [n.get("ldhName") for n in data.get("nameservers", [])]
    lines.append(f"Nameservers: {', '.join(ns) if ns else '[UNAVAILABLE]'}")
    st = data.get("status", [])
    lines.append(f"Status: {', '.join(st) if st else '[UNAVAILABLE]'}")
    return lines

def ssl_info(host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der = s.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return [f"TLS handshake FAILED: {e}", "Certificate may be invalid/self-signed"]
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return [f"Connection failed: {e}"]
    issuer = ", ".join("=".join(kv) for rdn in der.get("issuer", ()) for kv in rdn)
    subject = ", ".join("=".join(kv) for rdn in der.get("subject", ()) for kv in rdn)
    sans = ", ".join(v for k, v in der.get("subjectAltName", []) if k == "DNS")
    return [f"Host: {host}:{port}",
            f"Subject: {fmt(subject)}",
            f"Issuer: {fmt(issuer)}",
            f"Valid from: {fmt(der.get('notBefore'))}",
            f"Valid until: {fmt(der.get('notAfter'))}",
            f"Serial: {fmt(der.get('serialNumber'))}",
            f"SANs: {fmt(sans)}"]

def http_headers(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    r = http_get(url)
    lines = [f"URL: {r.url}", f"Status: {r.status_code} {r.reason}"]
    for k, v in r.headers.items():
        lines.append(f"{k}: {v}")
    return lines

def site_metadata(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    r = http_get(url)
    body = r.text[:200000]
    lines = [f"URL: {r.url}", f"Status: {r.status_code}"]
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    lines.append("Title: " + fmt(m.group(1).strip() if m else None))
    for prop, pat in (("Description", r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']'),
                      ("Generator", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']')):
        m = re.search(pat, body, re.I | re.S)
        lines.append(f"{prop}: {fmt(m.group(1).strip() if m else None)}")
    return lines

def asn_info(query):
    """ASN via RDAP (keyless). Accepts AS number, IP, or domain."""
    q = query.strip().upper().lstrip("AS")
    if not q.isdigit():
        # try IP
        try:
            ipaddress.ip_address(query.strip())
            data = lookup_ip(query.strip(), silent=True)
            q = (data.get("ASN") or "").split(" ")[0].lstrip("AS")
            if not q.isdigit():
                raise RuntimeError("no ASN resolved from IP")
        except (ValueError, RuntimeError) as e:
            if "no ASN" in str(e):
                raise
            # treat as domain
            data = lookup_ip(socket.gethostbyname(query.strip()), silent=True)
            q = (data.get("ASN") or "").split(" ")[0].lstrip("AS")
            if not q.isdigit():
                raise RuntimeError("no ASN resolved from domain")
    data = http_get_json(f"https://rdap.org/autnum/{q}")
    lines = [f"ASN: AS{data.get('startAutnum', q)}",
             f"Name: {fmt((data.get('name') or '').strip())}"]
    for ent in data.get("entities", []):
        v = (ent.get("vcardArray") or [None, []])[1]
        fn = next((x[3] for x in v if x[0] == "fn"), None)
        if fn:
            lines.append(f"Entity: {fn} ({', '.join(ent.get('roles', []))})")
    for rk in [r for r in data.get("remarks", []) if r.get("description")][:2]:
        lines.append(f"Remarks: {' / '.join(rk['description'][:2])}")
    return lines

# ------------------------------------------------------------------ #
#  REPORT SYSTEM
# ------------------------------------------------------------------ #

def clean(lines):
    return [re.sub(r"\033\[[0-9;]*m", "", str(l)) for l in lines]

def save_report(query_type, query_input, lines, source):
    os.makedirs(REPORT_DIR, exist_ok=True)
    now = datetime.datetime.now()
    fname = os.path.join(REPORT_DIR, f"report_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    plain = clean(lines)
    missing = [l for l in plain if "[UNAVAILABLE]" in l]
    with open(fname, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n        CYBER OSINT X — LOOKUP REPORT\n" + "=" * 60 + "\n")
        f.write(f"Date/Time  : {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Query type : {query_type}\n")
        f.write(f"Input      : {query_input}\n")
        f.write(f"Data source: {source}\n")
        f.write("-" * 60 + "\n\nRETRIEVED PUBLIC INFORMATION\n\n")
        f.write("\n".join(plain) + "\n")
        f.write("\n" + "-" * 60 + "\nMISSING / UNAVAILABLE FIELDS\n")
        f.write(("\n".join("  ! " + m for m in missing)) if missing else "  (none)\n")
        f.write("\n\n" + "=" * 60 + "\n"
                "Disclaimer: IP geolocation is approximate (city/network\n"
                "level) and does not represent a device's real location.\n"
                "This report contains publicly accessible information only.\n"
                + "=" * 60 + "\n")
    print(paint(f"  [+] Report saved → {fname}", C.GREEN))
    return fname

def view_reports():
    if not os.path.isdir(REPORT_DIR) or not os.listdir(REPORT_DIR):
        print(paint("  [!] No reports saved yet.", C.YELLOW)); return
    files = sorted(os.listdir(REPORT_DIR))
    for i, f in enumerate(files, 1):
        print(f"  {i:>2}. {f}")
    choice = input("\n  Report number to view (ENTER to cancel): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        with open(os.path.join(REPORT_DIR, files[int(choice) - 1]), encoding="utf-8") as f:
            print("\n" + f.read())

# ------------------------------------------------------------------ #
#  ACTIONS
# ------------------------------------------------------------------ #

def show_result_and_offer_save(qtype, inp, lines, source):
    print()
    box(qtype + " — " + str(inp), lines)
    s = input(paint("\n  Save this result to TXT? [y/N]: ", C.CYAN)).strip().lower()
    if s == "y":
        save_report(qtype, inp, lines, source)

def action_public_ip_lookup():
    raw = input("  Enter IP (v4/v6) or press ENTER to look up YOUR IP: ").strip()
    if raw:
        ip, err = validate_ip(raw)
        if err:
            print(paint(f"  [!] {err}", C.RED)); return
        target = str(ip)
    else:
        target, via = detect_my_ip()
        print(paint(f"  [i] Your public IP: {target} (via {via})", C.CYAN))
    cls = classify_ip(ipaddress.ip_address(target))
    if cls != "PUBLIC":
        print(paint(f"  [!] {target} is a {cls} address — no geolocation possible.", C.YELLOW))
        return
    data = lookup_ip(target)
    lines = [f"{k}: {fmt(v)}" for k, v in data.items()]
    lines.append("Note: geolocation is APPROXIMATE (city/network level).")
    show_result_and_offer_save("IP LOOKUP", target, lines, data["Source"])

def action_my_ip():
    progress("Detecting public IP")
    ip, via = detect_my_ip()
    lines = [f"Public IP: {ip}", f"Version: IPv{ipaddress.ip_address(ip).version}",
             f"Detection source: {via} (keyless)"]
    show_result_and_offer_save("MY PUBLIC IP", "auto-detect", lines, via)

def action_validator():
    raw = input("  Enter IP to validate: ").strip()
    ip, err = validate_ip(raw)
    if err:
        print(paint(f"  [!] INVALID — {err}", C.RED)); return
    lines = [f"IP: {raw}", "Valid: YES", f"Version: IPv{ip.version}",
             f"Classification: {classify_ip(ip)}",
             f"Compressed form: {ip.compressed}",
             f"Prefix length: {ip.max_prefixlen} bits"]
    show_result_and_offer_save("IP VALIDATOR", raw, lines, "python ipaddress (local)")

def action_phone_validate():
    if not HAS_PHONE:
        print(paint("  [!] pip install phonenumbers", C.RED)); return
    raw = input("  Phone number (e.g. +14155552671): ").strip()
    try:
        r = phone_validate(raw)
    except RuntimeError as e:
        print(paint(f"  [!] {e}", C.RED)); return
    show_result_and_offer_save("PHONE VALIDATION", raw, r["lines"],
                               "Google libphonenumber (local data, keyless)")

def action_phone_country():
    if not HAS_PHONE:
        print(paint("  [!] pip install phonenumbers", C.RED)); return
    raw = input("  Region code (US, GB, NP) or calling code (+44): ").strip()
    try:
        r = phone_country_info(raw)
    except RuntimeError as e:
        print(paint(f"  [!] {e}", C.RED)); return
    show_result_and_offer_save("PHONE COUNTRY INFO", raw, r["lines"],
                               "Google libphonenumber (local data, keyless)")

def action_domain_info():
    dom = input("  Domain (example.com): ").strip().lower()
    if not dom or "." not in dom:
        print(paint("  [!] Invalid domain.", C.RED)); return
    progress("Resolving & querying RDAP")
    try:
        lines = ["--- DNS/IP ---"] + dns_lookup(dom, full=False)
        try:
            lines.append(f"Resolved IP: {socket.gethostbyname(dom)}")
        except OSError:
            lines.append("Resolved IP: [UNAVAILABLE]")
        lines += ["", "--- RDAP (WHOIS) ---"] + rdap_lookup(dom)
        try:
            lines += ["", "--- METADATA ---"] + site_metadata(dom)
        except Exception as e:
            lines += ["", f"Metadata: [UNAVAILABLE] ({e})"]
    except Exception as e:
        print(paint(f"  [!] {e}", C.RED)); return
    show_result_and_offer_save("DOMAIN INFO", dom, lines, "DNS + rdap.org + HTTP (keyless)")

def action_dns():
    dom = input("  Domain: ").strip().lower()
    if not dom:
        print(paint("  [!] Invalid domain.", C.RED)); return
    progress("Querying DNS resolvers")
    show_result_and_offer_save("DNS LOOKUP", dom, dns_lookup(dom),
                               "DNS 8.8.8.8 / 1.1.1.1 / system (keyless)")

def action_reverse_dns():
    raw = input("  IP address: ").strip()
    ip, err = validate_ip(raw)
    if err:
        print(paint(f"  [!] {err}", C.RED)); return
    show_result_and_offer_save("REVERSE DNS", str(ip),
                               [f"IP: {ip}", f"Reverse DNS (PTR): {fmt(reverse_dns(str(ip)))}"],
                               "system resolver")

def action_asn():
    raw = input("  ASN number (e.g. 15169), IP, or domain: ").strip()
    try:
        lines = asn_info(raw)
    except Exception as e:
        print(paint(f"  [!] {e}", C.RED)); return
    show_result_and_offer_save("ASN INFO", raw, lines, "rdap.org (keyless)")

def action_ssl():
    host = input("  Hostname (example.com): ").strip()
    if not host:
        print(paint("  [!] Invalid host.", C.RED)); return
    progress("TLS handshake")
    show_result_and_offer_save("SSL CERTIFICATE", host, ssl_info(host),
                               "python ssl (live handshake, keyless)")

def action_headers():
    url = input("  URL (example.com): ").strip()
    if not url:
        print(paint("  [!] Invalid URL.", C.RED)); return
    progress("Sending HTTP request")
    try:
        lines = http_headers(url)
    except Exception as e:
        print(paint(f"  [!] {e}", C.RED)); return
    show_result_and_offer_save("HTTP HEADERS", url, lines, "live HTTP GET (keyless)")

ABOUT = [
    "CYBER OSINT X — ULTIMATE (Keyless Edition)",
    "No API keys. No tokens. No registration. 100% free sources.",
    "",
    "Keyless data sources:",
    "  - ip-api.com / ipwho.is   (IP geolocation, approximate)",
    "  - Google libphonenumber   (phone numbering plans)",
    "  - DNS 8.8.8.8 / 1.1.1.1   (DNS records)",
    "  - rdap.org                (WHOIS-equivalent + ASN)",
    "  - Live TLS handshake      (SSL certificates)",
    "",
    "Privacy notes:",
    "  - IP geolocation = city/network level, NOT device location.",
    "  - Phone tools use public numbering-plan data only.",
    "  - Only publicly accessible information is queried.",
]

MENU = [
    ("1",  "Public IP Lookup",          action_public_ip_lookup),
    ("2",  "My Public IP",              action_my_ip),
    ("3",  "IPv4 / IPv6 Validator",     action_validator),
    ("4",  "Phone Number Validator",    action_phone_validate),
    ("5",  "Phone Country Information", action_phone_country),
    ("6",  "Domain Information",        action_domain_info),
    ("7",  "DNS Lookup",                action_dns),
    ("8",  "Reverse DNS",               action_reverse_dns),
    ("9",  "ASN Information",           action_asn),
    ("10", "SSL Certificate Info",      action_ssl),
    ("11", "HTTP Headers",              action_headers),
    ("12", "Save Results to TXT",       None),
    ("13", "View Previous Reports",     view_reports),
    ("14", "About",                     None),
    ("15", "Exit",                      None),
]

def main_menu():
    while True:
        clear(); banner()
        print(paint("  ──────────────── MAIN MENU ────────────────", C.CYAN))
        for num, label, _ in MENU:
            print("   " + paint(f"[{num:>2}]", C.RED) + " " + label)
        print(paint("  ────────────────────────────────────────────", C.CYAN))
        choice = input(paint("\n  Select option: ", C.GREEN)).strip()
        if choice == "15":
            loading("Shutting down"); clear(); banner()
            print(paint("  Goodbye. Stay ethical.", C.RED)); sys.exit(0)
        if choice == "14":
            clear(); banner(); box("ABOUT", ABOUT); pause(); continue
        if choice == "12":
            print(paint("  [i] Saving is offered after every lookup result (y/N prompt).", C.CYAN))
            pause(); continue
        action = next((a for n, _, a in MENU if n == choice), None)
        if action is None:
            print(paint("  [!] Invalid choice.", C.RED)); time.sleep(1); continue
        clear(); banner()
        label = next(l for n, l, _ in MENU if n == choice)
        print(paint(f"  >>> {label} <<<\n", C.GREEN))
        try:
            action()
        except KeyboardInterrupt:
            print(paint("\n  [!] Cancelled.", C.YELLOW))
        except Exception as e:
            print(paint(f"  [!] ERROR: {e}", C.RED))
        pause()

if __name__ == "__main__":
    try:
        loading("Loading CYBER OSINT X")
        progress("Booting modules")
        main_menu()
    except KeyboardInterrupt:
        print("\n" + paint("  [!] Interrupted. Exiting.", C.YELLOW))
        sys.exit(0)
