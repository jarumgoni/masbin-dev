#!/usr/bin/env python3
"""
Quickstart example demonstrating DataShield SDK usage.
"""

import os
from datashield import DataShieldClient

def main():
    api_key = os.getenv("RAPIDAPI_KEY", "your-rapidapi-key-here")
    client = DataShieldClient(api_key=api_key)

    print("=== 1. Email Verification Demo ===")
    test_email = "alex@stripe.com"
    email_res = client.validate_email(test_email)
    print(f"Checking: {test_email}")
    print(f"Status: {email_res.get('status')}")
    print(f"Disposable: {email_res.get('is_disposable')}")
    print(f"Risk Score: {email_res.get('risk_score')}/100")

    print("\n=== 2. IP Intelligence Demo ===")
    test_ip = "185.249.227.213"
    ip_res = client.lookup_ip(test_ip)
    print(f"Checking IP: {test_ip}")
    print(f"Datacenter/Hosting: {ip_res.get('is_datacenter_proxy')}")
    print(f"Provider: {ip_res.get('datacenter_name')}")

if __name__ == "__main__":
    main()
