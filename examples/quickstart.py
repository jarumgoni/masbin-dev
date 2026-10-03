#!/usr/bin/env python3
"""
DataShield SDK Quickstart - Enterprise Verification & Threat Intelligence
"""

import os
import sys
from datashield import DataShieldClient, DataShieldError

def main():
    api_key = os.getenv("RAPIDAPI_KEY", "DEMO_KEY")
    client = DataShieldClient(api_key=api_key)

    print("=== 1. Email Verification & Burner Detection ===")
    test_email = "alex@stripe.com"
    try:
        email_res = client.validate_email(test_email)
        print(f"Target:      {email_res.email}")
        print(f"Verdict:     {email_res.verdict}")
        print(f"Disposable:  {email_res.is_disposable}")
        print(f"MX Records:  {email_res.mx_records_found}")
        print(f"Risk Score:  {email_res.risk_score} / 100")
    except DataShieldError as e:
        print(f"Validation notice: {e.message}")

    print("\n=== 2. IP Threat & Datacenter Intelligence ===")
    test_ip = "8.8.8.8"
    try:
        ip_res = client.lookup_ip(test_ip)
        print(f"IP:          {ip_res.ip}")
        print(f"Country:     {ip_res.country} ({ip_res.country_code})")
        print(f"ISP / Org:   {ip_res.org}")
        print(f"Datacenter:  {ip_res.is_datacenter}")
        print(f"Threat:      {ip_res.threat_level}")
    except DataShieldError as e:
        print(f"Lookup notice: {e.message}")

if __name__ == "__main__":
    main()
