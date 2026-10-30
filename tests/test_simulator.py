import importlib.util
from pathlib import Path

import pytest

SIM = Path(__file__).resolve().parents[1] / "simulator" / "simulate_attack.py"
spec = importlib.util.spec_from_file_location("simulate_attack", SIM)
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)


@pytest.mark.parametrize("target", ["127.0.0.1", "127.5.6.7", "127.255.255.254"])
def test_loopback_literals_accepted(target):
    assert sim.loopback_target(target) == target


@pytest.mark.parametrize("target", [
    "localhost",            # hostname: would need DNS
    "127.0.0.1.nip.io",     # hostname resolving to loopback today, anything tomorrow
    "10.0.0.1", "192.168.1.1", "8.8.8.8",
    "::1", "::ffff:127.0.0.1",  # IPv6, including the mapped form Python calls loopback
    "0177.0.0.1",           # octal spelling of 127.0.0.1
    "2130706433",           # integer spelling
    "",
])
def test_everything_else_refused(target):
    with pytest.raises(ValueError, match="127.0.0.0/8"):
        sim.loopback_target(target)


@pytest.mark.parametrize("args", [
    ["portscan", "--count", "1001"],
    ["portscan", "--count", "0"],
    ["udp_flood", "--interval", "0.0005"],
    ["portscan", "--target", "10.0.0.1"],
])
def test_caps_and_target_enforced_by_the_cli(args):
    with pytest.raises(SystemExit):
        sim.parse_args(args)


def test_defaults():
    assert (sim.parse_args(["portscan"]).count, sim.parse_args(["portscan"]).interval) == (200, 0.01)
    assert (sim.parse_args(["udp_flood"]).count, sim.parse_args(["udp_flood"]).interval) == (1000, 0.001)


def test_dry_run_sends_nothing(monkeypatch, capsys):
    monkeypatch.setattr(sim.socket, "socket", lambda *a, **k: pytest.fail("dry run opened a socket"))
    sim.main(["udp_flood", "--dry-run"])
    assert "would send 1000 udp_flood packets to 127.0.0.1" in capsys.readouterr().out


def test_udp_flood_uses_one_fixed_5_tuple(monkeypatch):
    calls = []

    class FakeSocket:
        def __init__(self, *a):
            pass

        def bind(self, addr):
            calls.append(("bind", addr))

        def sendto(self, data, addr):
            calls.append(("sendto", addr))

        def close(self):
            pass

    monkeypatch.setattr(sim.socket, "socket", FakeSocket)
    sim.main(["udp_flood", "--count", "3"])
    assert calls == [("bind", ("127.0.0.1", sim.UDP_SPORT))] + [("sendto", ("127.0.0.1", sim.UDP_DPORT))] * 3
