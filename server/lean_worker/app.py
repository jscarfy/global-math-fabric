import os, subprocess, tempfile, textwrap
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

TIMEOUT_SEC = int(os.environ.get("LEAN_TIMEOUT_SEC", "20"))

class VerifyReq(BaseModel):
    lean_source: str

class VerifyResp(BaseModel):
    ok: bool
    stdout: str = ""
    stderr: str = ""

@app.post("/verify", response_model=VerifyResp)
def verify(req: VerifyReq):
    src = req.lean_source
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "Main.lean")
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)

        # Use plain `lean` in the leanprover/lean4 image
        try:
            p = subprocess.run(
                ["lean", path],
                cwd=td,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SEC,
            )
            return VerifyResp(ok=(p.returncode == 0), stdout=p.stdout, stderr=p.stderr)
        except subprocess.TimeoutExpired as e:
            return VerifyResp(ok=False, stdout=e.stdout or "", stderr="timeout")
