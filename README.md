# Global Math Fabric (GMF)

GMF = 一个“可验证贡献”的全球数学协作网络：只有被服务器验证并签名写入账本的 `work_receipt` 才计分。

## Quick Start (Friend / Contributor)

### Linux / macOS (one-liner)
```bash
curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/scripts/dist/bootstrap_install.sh | bash -s -- \
  --api http://YOUR_SERVER:8080 \
  --device-id YOUR_DEVICE_ID \
  --platform linux \
  --topics nt,algebra

Windows (PowerShell)

iwr -useb https://raw.githubusercontent.com/<OWNER>/<REPO>/main/scripts/dist/bootstrap_install.ps1 | iex; `
  Install-GMFAgent -Api "http://YOUR_SERVER:8080" -DeviceId "YOUR_DEVICE_ID" -Platform "windows" -Topics "nt,algebra"

Stop/Uninstall: see scripts output.

Operator (You)
	•	Run server: docker compose up -d --build
	•	Create jobs: POST /work/jobs/create
	•	Credits: only sum of ledger work_receipt.awarded_credits

Security rule: never commit private keys.
