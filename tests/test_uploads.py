import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_drop_capabilities_empties_every_set():
    code = ("from backend.api.uploads import drop_capabilities; drop_capabilities(); "
            "print(open('/proc/self/status').read())")
    result = subprocess.run([sys.executable, "-c", code], check=False, cwd=REPO, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    caps = dict(line.split(":\t") for line in result.stdout.splitlines() if line.startswith("Cap"))
    assert int(caps["CapEff"], 16) == int(caps["CapPrm"], 16) == int(caps["CapAmb"], 16) == int(caps["CapInh"], 16) == 0
    assert "NoNewPrivs:\t1" in result.stdout
