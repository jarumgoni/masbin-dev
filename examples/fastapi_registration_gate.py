"""
FastAPI Registration Middleware / Gate using DataShield Python SDK
Prevents fake signups, burner email accounts, and malicious datacenter bots.
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr
from datashield import DataShieldClient, DataShieldError

app = FastAPI(title="SaaS User Registration Service with DataShield Guard")

# Initialize client using environment variable or direct key
shield = DataShieldClient(api_key="YOUR_RAPIDAPI_KEY")

class UserSignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

@app.post("/api/auth/register", status_code=201)
async def register_user(payload: UserSignupRequest, request: Request):
    # Extract client IP
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        # Step 1: Real-time Email Verification & Burner Detection
        email_check = shield.validate_email(payload.email)
        if email_check.is_disposable:
            raise HTTPException(
                status_code=400,
                detail=f"Registration rejected: Disposable email addresses ({email_check.domain}) are not permitted."
            )

        if not email_check.mx_records_found:
            raise HTTPException(
                status_code=400,
                detail="Registration rejected: Mail server for this domain does not accept incoming emails."
            )

        # Step 2: Datacenter / Proxy Bot Detection (Optional threshold)
        if client_ip not in ("127.0.0.1", "localhost"):
            ip_check = shield.lookup_ip(client_ip)
            if ip_check.is_datacenter and ip_check.threat_level == "HIGH":
                raise HTTPException(
                    status_code=403,
                    detail="Automated signup from datacenter proxy detected. Please use a residential connection."
                )

        # Step 3: Success - Save user to database
        return {
            "status": "success",
            "message": f"Welcome {payload.name}, your account has been provisioned.",
            "email_verdict": email_check.verdict,
            "risk_score": email_check.risk_score
        }

    except DataShieldError as e:
        # Graceful fallback: If API limit is hit or network drops, don't block legitimate users
        return {
            "status": "warning",
            "message": "User registered with basic validation (Fraud API temporarily bypassed)",
            "error": str(e)
        }
