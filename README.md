# Ip_lookup
┌────────────────────────────────────────────────┐
  │ IP LOOKUP — 8.8.8.8                            │
  ├────────────────────────────────────────────────┤
  │ Source:           ip-api.com (keyless)         │
  │ Country:          United States                │
  │ City:             Mountain View                │
  │ ISP:              Google LLC                   │
  │ ASN:              AS15169 Google LLC           │
  │ Reverse DNS:      dns.google                   │
  │ Note: geolocation is APPROXIMATE (city/netw... │
  └────────────────────────────────────────────────┘

  Save this result to TXT? [y/N]: y
  [+] Report saved → reports/report_20261117_143010.txt

  # CYBER OSINT X — ULTIMATE (Keyless Edition)

IP intelligence & public info lookup tool. **No API keys, no tokens,
no registration** — runs immediately after installing dependencies.

## Platforms
Android (Termux / Pydroid 3) · Linux · Windows

## Keyless Sources
- ip-api.com / ipwho.is — IP geolocation, ISP, ASN (fallback chain)
- Google libphonenumber — phone validation & numbering plans (local data)
- DNS 8.8.8.8 / 1.1.1.1 — A, AAAA, MX, NS, TXT, CNAME, SOA
- rdap.org — WHOIS-equivalent domain & ASN data
- Live TLS handshake — SSL certificate details

## Install

pip install -r requirements.txt
python ip_lookup.py

Termux: pkg install python, then pip install requests phonenumbers dnspython
Pydroid 3: use built-in pip installer, then run the script.

## Ethics
Queries only publicly accessible information. No private subscriber
data, no live location tracking, no telecom privacy circumvention.

## Disclaimer
IP geolocation is approximate (city/network level), NOT device location.
