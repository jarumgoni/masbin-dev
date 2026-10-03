# DataShield™ SDK & Developer Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-Hub-0052cc.svg)](https://rapidapi.com/user/ariebintoro)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/jarumgoni/masbin-dev/pulls)

Official developer client library and CLI for **DataShield Fraud Intelligence APIs**. High-speed validation, risk scoring, disposable email detection, phone carrier intelligence, and datacenter proxy checks.

Engineered for fintech, e-commerce checkouts, SaaS registration gates, and enterprise compliance.

---

## ⚡ Features

* **Email Intelligence**: Real-time syntax check, MX verification, disposable domain detector (1,200+ domains), and risk scoring (0-100).
* **Phone Intelligence**: Global E.164 parsing, international formatting, carrier lookup, and VoIP/virtual fraud scoring.
* **IP Threat Intelligence**: Rapid detection of datacenter proxies, VPNs, hosting providers (AWS, GCP, Cloudflare, Hetzner, etc.), and fraud score.
* **Domain Security Audit**: Comprehensive DNS health, MX redundancy, and reputation checks.
* **Ultra-Low Latency**: Sub-50ms response times, built-in LRU caching, and connection pooling.

---

## 🚀 Quick Start (Python)

### 1. Installation

```bash
pip install datashield-sdk
```

*(Or clone this repository and install locally)*
```bash
git clone https://github.com/jarumgoni/masbin-dev.git
cd masbin-dev
pip install -e .
```

### 2. Usage

Get your API Key from [RapidAPI DataShield Console](https://rapidapi.com/user/ariebintoro).

```python
from datashield import DataShieldClient

# Initialize client with your RapidAPI Key
client = DataShieldClient(api_key="YOUR_RAPIDAPI_KEY")

# 1. Validate Email & Detect Disposable Accounts
email_res = client.validate_email("test@tempmail.com")
print(f"Valid: {email_res.is_valid}")
print(f"Disposable: {email_res.is_disposable}")
print(f"Risk Score: {email_res.risk_score}/100")

# 2. Check IP Address & Datacenter Proxy
ip_res = client.lookup_ip("185.249.227.213")
print(f"Country: {ip_res.country}")
print(f"Is Datacenter/Proxy: {ip_res.is_datacenter}")
print(f"Provider: {ip_res.datacenter_name}")

# 3. Verify International Phone Number
phone_res = client.verify_phone("+14155552671")
print(f"Valid: {phone_res.is_valid}")
print(f"Carrier: {phone_res.carrier}")
print(f"Risk Score: {phone_res.risk_score}")
```

---

## 📦 Node.js / JavaScript Example

```javascript
import { DataShield } from 'datashield-node';

const client = new DataShield({ apiKey: process.env.RAPIDAPI_KEY });

const result = await client.email.validate('user@example.com');
console.log(result);
```

---

## 🛡️ API Endpoints Reference

All requests are securely routed through RapidAPI Gateway with automatic DDoS filtering and 99.9% uptime SLA:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/v1/email/validate` | `GET` | Email syntax, disposable filter, MX record verification, and fraud score |
| `/v1/phone/validate` | `GET` | Global E.164 phone verification, carrier intelligence, and VoIP risk |
| `/v1/ip/lookup` | `GET` | IP geolocation, ISP classification, and threat assessment |
| `/v1/ip/check-proxy` | `GET` | High-speed boolean check: returns true if IP belongs to a hosting/proxy provider |

---

## 🤝 Community & Support

* **API Portal**: [DataShield on RapidAPI Hub](https://rapidapi.com/user/ariebintoro)
* **Issues & Bug Reports**: [GitHub Issues](https://github.com/jarumgoni/masbin-dev/issues)
* **Author**: masbin (`masbin-dev`)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
