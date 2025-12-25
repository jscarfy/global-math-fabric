#!/usr/bin/env python3
import json, sys
obj = json.load(sys.stdin)
sys.stdout.write(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
