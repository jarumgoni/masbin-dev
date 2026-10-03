# DataShield™ Python SDK & Developer Tooling

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/jarumgoni/masbin-dev)
[![PyPI version](https://img.shields.io/badge/pypi-v1.1.0-blue.svg)](https://github.com/jarumgoni/masbin-dev)
[![Python 3.9 | 3.10 | 3.11 | 3.12](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![RapidAPI Hub](https://img.shields.io/badge/RapidAPI-Verified%20Provider-0052cc.svg)](https://rapidapi.com/ariebintoro/api/datashield-email-verification-fraud-detection-api)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Official enterprise Python client library and CLI for the **DataShield™ Fraud Intelligence & Verification Engine**. Built for high-throughput SaaS registration gates, payment checkouts, cold outreach hygiene, and B2B compliance.

* **Documentation & Sandbox**: [RapidAPI Hub Console](https://rapidapi.com/ariebintoro/api/datashield-email-verification-fraud-detection-api)
* **Production Web Portal**: [prochatcommerce.com](https://prochatcommerce.com)

---

## ⚡ Core Architecture & Capabilities

DataShield operates a multi-tier heuristic inspection pipeline that evaluates incoming payloads in parallel:

```
 Incoming Request (Email / IP / Phone)
               │
               ▼
┌──────────────────────────────────────────────┐
│ Tier 1: RFC 5322 Syntax & IANA TLD Sanitizer │ (p50: 1.2ms)
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────────────────────────────────────────┐
│ Tier 2: Real-Time Burner & Disposable Radar  │ (p50: 3.8ms)
│         (120k+ live burner domains feed)     │
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────────────────────────────────────────┐
│ Tier 3: Zero-Ping Mail Exchange (MX) DNS     │ (p50: 7.4ms)
│         Health & Redundancy Verification     │
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────────────────────────────────────────┐
│ Tier 4: IP Geolocation, BGP ASN, & Datacenter│ (p50: 8.4ms)
│         Proxy Scoring (AWS, GCP, Hetzner)    │
└──────────────────────┬───────────────────────┘
                       ▼
       Structured JSON Verdict & Risk Score (0-100)
```

### Key Performance Benchmarks

| Region | Gateway Pop | p50 Latency | p95 Latency | Cold Cache SLA |
| :--- | :--- | :--- | :--- | :--- |
| **Frankfurt (fra1)** | Central EU Edge | **8.4 ms** | **18.2 ms** | 99.99% |
| **Singapore (sin1)** | APAC Primary | **14.2 ms** | **24.6 ms** | 99.98% |
| **US-East (iad1)** | N. Virginia Hub | **19.8 ms** | **31.0 ms** | 99.99% |
| **London (lhr1)** | UK West End | **11.1 ms** | **21.5 ms** | 99.99% |

---

## 📦 Installation

```bash
# Via pip
pip install datashield-sdk

# Or directly from source
git clone https://github.com/jarumgoni/masbin-dev.git
cd masbin-dev
pip install -e .
```

---

## 🚀 Quickstart

### 1. Synchronous Client (Default)

```python
from datashield import DataShieldClient, DataShieldError

# Initialize with your RapidAPI Key
client = DataShieldClient(api_key="YOUR_RAPIDAPI_KEY")

try:
    # Validate single email
    result = client.validate_email("prospect@burner-inbox.xyz")
    
    print(f"Target:      {result.email}")
    print(f"Verdict:     {result.verdict}")        # ALLOW or REJECT
    print(f"Disposable:  {result.is_disposable}")   # True / False
    print(f"MX Records:  {result.mx_records_found}")# True / False
    print(f"Risk Score:  {result.risk_score} / 100") # 0 (safe) to 100 (fraud)

    if result.is_disposable:
        print("[!] Dropped fake account attempt.")

except DataShieldError as err:
    print(f"API Error ({err.status_code}): {err.message}")
```

### 2. High-Throughput Asyncio Client (`AsyncDataShieldClient`)

Ideal for FastAPI, Tornado, Starlette, or asynchronous batch jobs:

```python
import asyncio
from datashield import AsyncDataShieldClient

async def run_checks():
    client = AsyncDataShieldClient(api_key="YOUR_RAPIDAPI_KEY")
    
    # Run email and IP checks concurrently
    email_task = client.validate_email("user@startup.io")
    ip_task = client.lookup_ip("8.8.8.8")
    
    email_res, ip_res = await asyncio.gather(email_task, ip_task)
    
    print(f"Email Status: {email_res.verdict}")
    print(f"IP Datacenter: {ip_res.is_datacenter} ({ip_res.org})")

asyncio.run(run_checks())
```

---

## 🛠️ CLI Usage (`datashield-cli`)

The SDK ships with a zero-config terminal executable for developers and DevOps engineers:

```bash
# Set your key once
export RAPIDAPI_KEY="YOUR_KEY_HERE"

# 1. Inspect an email address
datashield email alex@disposable-inbox.com

# 2. Inspect an IP address
datashield ip 8.8.8.8

# 3. Audit a domain's mail hygiene
datashield domain stripe.com

# 4. Return raw JSON for jq pipelines
datashield email user@example.com --json | jq .
```

---

## 🛡️ Production Framework Recipes

### FastAPI User Registration Gate

```python
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
from datashield import DataShieldClient

app = FastAPI()
shield = DataShieldClient(api_key="YOUR_RAPIDAPI_KEY")

class RegisterPayload(BaseModel):
    name: str
    email: EmailStr
    password: str

@app.post("/auth/register")
def register(user: RegisterPayload, req: Request):
    # Step 1: Real-time fraud detection
    verification = shield.validate_email(user.email)
    
    if verification.is_disposable:
        raise HTTPException(
            status_code=400,
            detail="Temporary and disposable email providers are prohibited."
        )
        
    if not verification.mx_records_found:
        raise HTTPException(
            status_code=400,
            detail="The specified email domain cannot receive incoming messages."
        )
        
    # Step 2: Proceed with account provisioning
    return {"status": "ok", "user_id": "usr_991823"}
```

---

## 📑 Exception Handling Hierarchy

The SDK maps all HTTP status codes to explicit, typed exceptions:

```
DataShieldError (Base)
 ├── AuthenticationError      (HTTP 401 / 403 - Invalid API Key)
 ├── RateLimitExceededError   (HTTP 429 - Plan Quota or Rate Burst)
 ├── InvalidParameterError    (HTTP 400 / 422 - Malformed Input)
 ├── ResourceNotFoundError    (HTTP 404 - Endpoint Unavailable)
 └── ServerUnavailableError   (HTTP 500 / 502 / 503 - Upstream Outage)
```

Example defensive implementation:

```python
from datashield import DataShieldClient, RateLimitExceededError, AuthenticationError

client = DataShieldClient(api_key="YOUR_KEY")

try:
    res = client.validate_email("test@example.com")
except AuthenticationError:
    # Alert DevOps to rotate or verify API credentials
    pass
except RateLimitExceededError:
    # Quota exceeded - upgrade tier on RapidAPI or throttle locally
    pass
```

---

## 🧪 Running Unit Tests

```bash
# Run test suite
python3 -m unittest discover tests -v

# Run with coverage (if pytest-cov installed)
pytest --cov=datashield tests/
```

---

## 🔒 Security & Privacy

* DataShield does **not** store plaintext PII or resell user contact records.
* In-flight traffic is encrypted with TLS 1.3 / AES-256-GCM.
* Enterprise edge nodes enforce strict multi-tenant isolation.

---

## 📄 License & Commercial Terms

* **License**: MIT License. See [LICENSE](LICENSE) for details.
* **API Access & Billing**: Subscriptions, keys, and automated metering are managed via [RapidAPI Hub DataShield Portal](https://rapidapi.com/ariebintoro/api/datashield-email-verification-fraud-detection-api/pricing).
* **Maintainer**: masbin (`masbin-dev@users.noreply.github.com`)
