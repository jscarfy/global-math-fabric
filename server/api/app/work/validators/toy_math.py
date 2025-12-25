"""
MVP validator: toy_math
payload:
  {"problem": "add", "a": 2, "b": 3}
client output:
  {"answer": 5, "explain": "...optional..."}
"""

def validate(payload: dict, output: dict) -> tuple[bool, str]:
    try:
        if payload.get("problem") == "add":
            a = int(payload["a"]); b = int(payload["b"])
            ans = int(output.get("answer"))
            return (ans == a + b, "ok" if ans == a + b else "wrong_answer")
        return (False, "unknown_problem")
    except Exception as e:
        return (False, f"exception:{e}")
