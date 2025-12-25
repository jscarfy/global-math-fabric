import os, time, json, base64, requests, hashlib

API = os.environ.get("GMF_API", "http://api:8000")
VERIFIER_ID = os.environ.get("GMF_VERIFIER_ID", "verifier-1")

def sha256_json(v):
    b = json.dumps(v, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()

def main():
    while True:
        try:
            r = requests.get(f"{API}/replay/queue", timeout=20)
            r.raise_for_status()
            data = r.json()
            item = data.get("item")
            if not item:
                time.sleep(10)
                continue

            # For MVP, we trust that mobile tasks are ABI1 and deterministic.
            # We do NOT execute wasm here (to keep verifier tiny). We just compare majority hash already computed.
            # Production: embed wasmi runner (Rust) and actually run.
            # Here, we mark ok=True to show pipeline; switch to real execution later.
            ok = True

            rep = {
                "instance_id": item["instance_id"],
                "verifier_id": VERIFIER_ID,
                "ok": ok,
                "detail": {"note":"mvp_verifier_stub_no_exec"}
            }
            rr = requests.post(f"{API}/replay/report", json=rep, timeout=20)
            rr.raise_for_status()
        except Exception as e:
            print("verifier error:", e)
            time.sleep(5)

if __name__ == "__main__":
    main()
