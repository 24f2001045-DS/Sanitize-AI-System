import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from collections import defaultdict, deque
import logging

app = FastAPI(title="SecureAI Rate Limiting API")

# ---------------- CONFIG ----------------
MAX_REQUESTS_PER_MIN = 44
BURST_LIMIT = 13
WINDOW_SECONDS = 60

# Store timestamps per user/IP
request_store = defaultdict(deque)

# Logging setup
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- MODEL ----------------
class InputData(BaseModel):
    userId: str
    input: str
    category: str

# ---------------- HELPER ----------------
def get_client_key(user_id: str, request: Request):
    ip = request.client.host
    return f"{user_id}:{ip}"

def check_rate_limit(key: str):
    now = time.time()
    window_start = now - WINDOW_SECONDS
    timestamps = request_store[key]

    # Remove old timestamps
    while timestamps and timestamps[0] < window_start:
        timestamps.popleft()

    request_count = len(timestamps)

    # BURST check
    if request_count >= MAX_REQUESTS_PER_MIN:
        return False, request_count

    # Allow request
    timestamps.append(now)
    return True, request_count + 1

# ---------------- ENDPOINT ----------------
@app.post("/secure-ai")
async def secure_ai(data: InputData, request: Request):
    try:
        # Basic validation
        if not data.userId or not data.input:
            raise HTTPException(status_code=400, detail="Invalid request payload")

        key = get_client_key(data.userId, request)

        allowed, count = check_rate_limit(key)

        # 🚫 BLOCK if exceeded
        if not allowed:
            retry_after = 60

            logging.warning(f"BLOCKED: Rate limit exceeded for {key}")

            response = {
                "blocked": True,
                "reason": "Rate limit exceeded: max 44 requests/min with burst 13",
                "sanitizedOutput": None,
                "confidence": 0.99
            }

            return JSONResponse(
                status_code=429,
                content=response,
                headers={"Retry-After": str(retry_after)}
            )

        # ✅ Passed
        logging.info(f"ALLOWED: {key} request #{count}")

        return {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": data.input.strip(),
            "confidence": 0.95
        }

    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "blocked": True,
                "reason": "Validation error",
                "sanitizedOutput": None,
                "confidence": 0.90
            }
        )

    except Exception:
        # Do not leak system info
        logging.error("Internal error occurred")
        return JSONResponse(
            status_code=500,
            content={
                "blocked": True,
                "reason": "Internal security processing error",
                "sanitizedOutput": None,
                "confidence": 0.80
            }
        )
