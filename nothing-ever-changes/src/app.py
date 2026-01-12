import os
import secrets
import time

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from config import load_config
from model import get_model_bundle, predict_top1, set_deterministic
from verification import Verifier
import pow


set_deterministic(0)

bundle = get_model_bundle(device="cpu")
config = load_config()
pow_difficulty = int(os.environ.get("POW_DIFFICULTY", "0"))
pow_ttl_seconds = int(os.environ.get("POW_TTL_SECONDS", "300"))
pow_store: dict[str, tuple[str, float]] = {}


def predict_fn(image):
    return predict_top1(image, bundle=bundle)


verifier = Verifier(config=config, predict_fn=predict_fn)

app = FastAPI()


def _cleanup_pow_store(now: float) -> None:
    expired = [token for token, (_, exp) in pow_store.items() if exp <= now]
    for token in expired:
        pow_store.pop(token, None)


def issue_pow() -> tuple[str, str] | None:
    if pow_difficulty <= 0:
        return None
    now = time.time()
    _cleanup_pow_store(now)
    challenge = pow.get_challenge(pow_difficulty)
    token = secrets.token_urlsafe(24)
    pow_store[token] = (challenge, now + pow_ttl_seconds)
    return token, challenge


def verify_pow(token: str | None, solution: str | None) -> bool:
    if pow_difficulty <= 0:
        return True
    if not token or not solution:
        return False
    now = time.time()
    _cleanup_pow_store(now)
    entry = pow_store.get(token)
    if not entry:
        return False
    challenge, exp = entry
    if exp <= now:
        pow_store.pop(token, None)
        return False
    ok = pow.verify_challenge(challenge, solution)
    if ok:
        pow_store.pop(token, None)
    return ok


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/pow")
def get_pow():
    if pow_difficulty <= 0:
        return {"enabled": False}
    issued = issue_pow()
    if not issued:
        return {"enabled": False}
    token, challenge = issued
    return {
        "enabled": True,
        "difficulty": pow_difficulty,
        "ttl_seconds": pow_ttl_seconds,
        "token": token,
        "challenge": challenge,
    }

@app.post("/submit")
async def submit(
    file: UploadFile = File(...),
    x_pow_token: str | None = Header(default=None, alias="X-PoW-Token"),
    x_pow_solution: str | None = Header(default=None, alias="X-PoW-Solution"),
):
    if not verify_pow(x_pow_token, x_pow_solution):
        raise HTTPException(status_code=403, detail="pow_required")

    data = await file.read()
    if len(data) > config.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="file_too_large")

    ok = verifier.verify_zip(data)
    if ok:
        return JSONResponse({"success": True, "flag": config.flag})
    return JSONResponse({"success": False})
