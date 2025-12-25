# GMF Tasks Schema v1

## TaskSpec
- protocol: "gmf/task/v1"
- task_id: string
- kind: string
- params: json object
- credit_micro_total: int64
- replicas: int (>=1)  # number of independent devices needed to agree

## Result agreement (MVP)
For tasks with replicas>=2:
- server accepts when it receives >= replicas submissions with identical `result_core`.
- credits per device = floor(credit_micro_total / replicas)

## kind = "lean_check"
params:
- git_url: string
- rev: string (commit SHA)
- subdir: string ("" or path)
- cmd: array of strings (default: ["lake","build"])
- use_mathlib_cache: bool (default true)

result_core:
- ok: bool
- exit_code: int
