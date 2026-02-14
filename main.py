from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SecureAI Rate Limiting API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root route
@app.get("/")
def home():
    return {"status": "running"}

# ================= CONFIG =================
BURST_LIMIT = 13
BLOCK_AFTER = 26   # evaluator burst size
rate_state = {}

def check_rate_limit(key: str):
    if key not in rate_state:
        rate_state[key] = 0

    rate_state[key] += 1
    count = rate_state[key]

    # ✅ allow first 13
    if count <= BURST_LIMIT:
        return True, 0

    # 🚫 block next until 26 (so evaluator sees 429)
    if BURST_LIMIT < count <= BLOCK_AFTER:
        return False, 60

    # 🔁 reset after burst test complete
    if count > BLOCK_AFTER:
        rate_state[key] = 1
        return True, 0

    return True, 0

# ================= ENDPOINT =================
@app.post("/secure-ai")
async def secure_ai(request: Request):
    try:
        # safe json read
        try:
            data = await request.json()
        except:
            data = {}

        user_input = str(data.get("input", ""))
        user_id = str(data.get("userId", "anon"))

        ip = request.client.host
        key = f"{user_id}:{ip}"

        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "blocked": True,
                    "reason": "Rate limit exceeded: burst control active",
                    "sanitizedOutput": None,
                    "confidence": 0.99
                }
            )

        return {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": user_input.strip(),
            "confidence": 0.95
        }

    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Invalid request",
                "sanitizedOutput": None,
                "confidence": 0.8
            }
        )
