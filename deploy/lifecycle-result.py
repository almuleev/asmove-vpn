"""Read the result of the privileged, independently scheduled lifecycle runner."""
import json
from pathlib import Path
import re
import sys

try:
    request = json.loads(sys.stdin.read(65537))
    job = request["job_id"]
    stage = sys.argv[1]
    if not re.fullmatch(r"[a-f0-9]{32}", job) or stage not in {"provisioning", "verifying", "publishing"}:
        raise ValueError("Invalid request")
    path = Path("/var/lib/nodeguard-lifecycle-results") / (job + "-" + stage + ".json")
    result = json.loads(path.read_text()) if path.is_file() else {"ready": False, "published": False, "pending": True}
    print(json.dumps(result))
except (ValueError, KeyError, OSError, IndexError):
    sys.exit(1)
