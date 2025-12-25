import os, json
from typing import Any, Dict, Optional, Tuple, List

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def checkpoints_dir() -> str:
    return os.environ.get("GMF_LEDGER_CHECKPOINTS_DIR", "ledger/checkpoints")

def latest_checkpoint_entries() -> int:
    d = checkpoints_dir()
    try:
        files = [fn for fn in os.listdir(d) if fn.startswith("checkpoint-") and fn.endswith(".json")]
        if not files:
            return 0
        files.sort()
        cp = load_json(os.path.join(d, files[-1]))
        return int(cp.get("entries") or 0)
    except Exception:
        return 0

def select_active_rules(registry: Dict[str, Any], head_entries: int) -> Dict[str, Any]:
    """
    Pick the highest effective_from_checkpoint_entries <= head_entries.
    Falls back to first entry.
    """
    rules_list: List[Dict[str,Any]] = list(registry.get("rules") or [])
    if not rules_list:
        raise RuntimeError("rules registry empty")

    # sort by effective_from_checkpoint_entries ascending
    def eff(x: Dict[str,Any]) -> int:
        try:
            return int(x.get("effective_from_checkpoint_entries") or 0)
        except Exception:
            return 0

    rules_list.sort(key=eff)
    chosen = rules_list[0]
    for r in rules_list:
        if eff(r) <= head_entries:
            chosen = r
        else:
            break
    return chosen
