#!/usr/bin/env python3
"""Execute one already phone-verified, operator-approved exact recovery on the local runtime."""
import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("recovery_id")
parser.add_argument("request_hash", help="Exact persisted 64-character request commitment; never a password")
args = parser.parse_args()
try:
    if str(uuid.UUID(args.recovery_id)) != args.recovery_id or not re.fullmatch(r"[0-9a-f]{64}", args.request_hash):
        raise ValueError()
except ValueError:
    parser.error("A canonical recovery UUID and exact lowercase request commitment are required")

request = urllib.request.Request(
    "http://127.0.0.1:8081/tasks/recover-account",
    data=urllib.parse.urlencode({"recoveryId": args.recovery_id, "requestHash": args.request_hash}).encode("ascii"),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
)
try:
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as response:
        result = response.read(257).decode("ascii").strip()
    if not re.fullmatch(r"status=[0-9]{3} (?:state=[a-z_]+|code=[A-Z_]+)", result):
        raise ValueError()
    print(result)
    sys.exit(0 if result == "status=200 state=active" else 2)
except (OSError, ValueError, urllib.error.HTTPError):
    # The runtime may still be processing. Reconcile the same operation; never invent another grant.
    print("Recovery outcome unavailable; inspect or retry the same exact operation.", file=sys.stderr)
    sys.exit(3)
