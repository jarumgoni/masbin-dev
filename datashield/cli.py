"""
DataShield Command Line Interface (CLI)
Enables instantaneous threat and fraud lookups from developer terminals.
"""

import sys
import os
import json
import argparse
from typing import Optional

from .client import DataShieldClient
from .exceptions import DataShieldError

def main(args: Optional[list] = None):
    parser = argparse.ArgumentParser(
        prog="datashield",
        description="DataShield Enterprise Fraud & Verification CLI"
    )
    parser.add_argument("--key", default=os.getenv("DATASHIELD_API_KEY") or os.getenv("RAPIDAPI_KEY"),
                        help="RapidAPI key or set via RAPIDAPI_KEY env var")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    subparsers = parser.add_subparsers(dest="command", help="Available verification subcommands")

    # Email command
    email_parser = subparsers.add_parser("email", help="Verify single email address")
    email_parser.add_argument("email", type=str, help="Target email string")

    # Domain command
    domain_parser = subparsers.add_parser("domain", help="Audit domain DNS and MX posture")
    domain_parser.add_argument("domain", type=str, help="Target domain name")

    # IP command
    ip_parser = subparsers.add_parser("ip", help="Lookup IP threat intelligence and ASN")
    ip_parser.add_argument("ip", type=str, help="Target IPv4 or IPv6 address")

    # Phone command
    phone_parser = subparsers.add_parser("phone", help="Verify phone number and carrier")
    phone_parser.add_argument("phone", type=str, help="Target phone number")

    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        sys.exit(0)

    if not parsed.key:
        sys.stderr.write("Error: Missing API key. Pass --key <KEY> or set RAPIDAPI_KEY environment variable.\n")
        sys.exit(1)

    client = DataShieldClient(api_key=parsed.key)

    try:
        if parsed.command == "email":
            res = client.validate_email(parsed.email)
            if parsed.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                verdict_color = "\033[92m" if res.verdict == "ALLOW" else "\033[91m"
                reset = "\033[0m"
                print(f"Target:     {res.email}")
                print(f"Domain:     {res.domain}")
                print(f"Verdict:    {verdict_color}{res.verdict}{reset}")
                print(f"Disposable: {'YES (BLOCKED)' if res.is_disposable else 'NO (CLEAN)'}")
                print(f"MX Records: {'Valid' if res.mx_records_found else 'Missing'}")
                print(f"Risk Score: {res.risk_score} / 100")

        elif parsed.command == "domain":
            res = client.audit_domain(parsed.domain)
            if parsed.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"Domain:     {res.domain}")
                print(f"MX Config:  {'Present' if res.has_mx else 'None'}")
                print(f"Risk Score: {res.risk_score} / 100")

        elif parsed.command == "ip":
            res = client.lookup_ip(parsed.ip)
            if parsed.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"IP:         {res.ip}")
                print(f"Country:    {res.country} ({res.country_code})")
                print(f"ISP / ASN:  {res.org} ({res.asn})")
                print(f"Datacenter: {'YES (PROXY/VPN)' if res.is_datacenter else 'NO (RESIDENTIAL)'}")
                print(f"Threat:     {res.threat_level}")

        elif parsed.command == "phone":
            res = client.verify_phone(parsed.phone)
            if parsed.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"Phone:      {res.phone}")
                print(f"Carrier:    {res.carrier}")
                print(f"VoIP:       {'YES' if res.is_voip else 'NO'}")
                print(f"Valid:      {'YES' if res.is_valid else 'NO'}")

    except DataShieldError as e:
        sys.stderr.write(f"DataShield API Error [{e.status_code}]: {e.message}\n")
        sys.exit(2)

if __name__ == "__main__":
    main()
