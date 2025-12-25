from fastapi import FastAPI

app = FastAPI(title="Global Math Fabric API")

@app.get("/health")
def health():
    return {"ok": True}

# Minimal task endpoints (stub)
@app.post("/tasks/lease")
def lease_task():
    # TODO: implement lease/claim logic with DB + redis locks
    return {"task_id": None}

@app.post("/tasks/report")
def report_result():
    # TODO: implement result submission + verification queue
    return {"accepted": False}
