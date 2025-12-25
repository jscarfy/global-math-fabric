import os, hashlib, math
from datetime import datetime, timezone

def _geti(k: str, d: int) -> int:
    try:
        return int(os.environ.get(k, str(d)))
    except Exception:
        return d

def _getf(k: str, d: float) -> float:
    try:
        return float(os.environ.get(k, str(d)))
    except Exception:
        return d

def risk_halflife_days() -> float:
    return _getf("GMF_RISK_HALFLIFE_DAYS", 7.0)

def decay_risk(score: float, last_updated_at: datetime | None, now: datetime) -> float:
    if score <= 0:
        return 0.0
    if not last_updated_at:
        return float(score)
    # exponential decay with half-life
    dt = (now - last_updated_at).total_seconds()
    if dt <= 0:
        return float(score)
    half = max(1e-6, risk_halflife_days() * 86400.0)
    lam = math.log(2.0) / half
    return float(score) * math.exp(-lam * dt)

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def result_weight_from_risk(risk: float) -> float:
    # risk in [0,100+] -> weight in [min,max]
    wmin = _getf("GMF_RESULT_WEIGHT_MIN", 0.25)
    wmax = _getf("GMF_RESULT_WEIGHT_MAX", 1.0)
    # smooth: weight = wmax - (wmax-wmin)*(risk/100)
    return clamp(wmax - (wmax - wmin) * (max(0.0, risk) / 100.0), wmin, wmax)

def reward_mult_from_risk(risk: float) -> float:
    rmin = _getf("GMF_REWARD_MULT_MIN", 0.2)
    rmax = _getf("GMF_REWARD_MULT_MAX", 1.0)
    return clamp(rmax - (rmax - rmin) * (max(0.0, risk) / 100.0), rmin, rmax)

def ip_prefix(ip: str | None) -> str:
    if not ip:
        return ""
    # keep only coarse prefix (privacy-minimal)
    if ":" in ip:
        # IPv6: keep first 3 hextets
        parts = ip.split(":")
        return ":".join(parts[:3])
    # IPv4: keep first 2 octets
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else ip

def fingerprint_hash(user_agent: str | None, device_id: str | None, ip: str | None) -> str:
    ua = (user_agent or "").strip()
    did = (device_id or "").strip()
    ipp = ip_prefix(ip)
    msg = f"ua={ua}|did={did}|ip={ipp}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()
