import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_drop_capabilities_empties_every_set():
    code = ("from backend.api.uploads import drop_capabilities; drop_capabilities(); "
            "print(open('/proc/self/status').read())")
    status = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, check=True).stdout
    caps = dict(line.split(":\t") for line in status.splitlines() if line.startswith("Cap"))
    assert int(caps["CapEff"], 16) == int(caps["CapPrm"], 16) == int(caps["CapAmb"], 16) == 0
