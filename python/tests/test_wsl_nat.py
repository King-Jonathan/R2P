"""WSL2 NAT detection, host-LAN filter, and relay start/stop."""

from r2p.platform.wsl_nat import (
    WslLanRelay,
    encode_powershell,
    filter_host_lan_ips,
    parse_default_gateway,
    parse_ipv4_lines,
    parse_resolv_nameservers,
    relay_script,
    should_start_relay,
    wsl_flavor,
)


class _LiveProc:
    def __init__(self) -> None:
        self.code = None

    def poll(self):
        return self.code

    def terminate(self) -> None:
        self.code = 0

    def wait(self, timeout=None) -> int:
        self.code = 0 if self.code is None else self.code
        return self.code

    def kill(self) -> None:
        self.code = 1


class _DeadProc(_LiveProc):
    def __init__(self) -> None:
        super().__init__()
        self.code = 1


def test_wsl_flavor_from_kernel_and_env():
    assert wsl_flavor(environ={}, release="6.8.0-generic") == "none"
    assert wsl_flavor(environ={}, release="5.15.153.1-microsoft-standard-WSL2") == "wsl2"
    assert wsl_flavor(environ={}, release="4.4.0-19041-Microsoft") == "wsl1"
    assert wsl_flavor(environ={"WSL_DISTRO_NAME": "Ubuntu"}, release="6.8.0-generic") == "wsl2"


def test_should_start_relay_only_wsl2_nat():
    virt = ["172.24.12.10"]
    lan = ["192.168.1.5"]
    assert should_start_relay("none", "nat", virt) is False
    assert should_start_relay("wsl1", "nat", virt) is False
    assert should_start_relay("wsl2", "mirrored", lan) is False
    assert should_start_relay("wsl2", "mirrored", virt) is False
    assert should_start_relay("wsl2", "nat", lan) is False
    assert should_start_relay("wsl2", "nat", virt) is True
    assert should_start_relay("wsl2", None, virt) is True
    assert should_start_relay("wsl2", None, lan) is False


def test_filter_host_lan_ips_drops_vswitch_keeps_wifi():
    lan = filter_host_lan_ips(
        ["127.0.0.1", "172.24.0.1", "192.168.1.5", "169.254.1.1", "172.24.12.10"],
        guest_ip="172.24.12.10",
        gateway="172.24.0.1",
    )
    assert lan == ["192.168.1.5"]


def test_filter_keeps_unrelated_172_corporate_lan():
    lan = filter_host_lan_ips(
        ["172.16.0.50", "172.24.0.1"],
        guest_ip="172.24.12.10",
        gateway="172.24.0.1",
    )
    assert lan == ["172.16.0.50"]


def test_filter_drops_vswitch_on_same_slash16():
    lan = filter_host_lan_ips(
        ["192.168.1.5", "172.24.192.1"],
        guest_ip="172.24.207.69",
        gateway=None,
    )
    assert lan == ["192.168.1.5"]


def test_parse_ipv4_lines_and_gateway():
    assert parse_ipv4_lines("192.168.1.5\nnot-an-ip\n192.168.1.5\n10.0.0.2") == [
        "192.168.1.5",
        "10.0.0.2",
    ]
    route = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    assert parse_default_gateway(route) == "192.168.0.1"
    resolv = "# comment\nnameserver 172.24.0.1\nnameserver 1.1.1.1\n"
    assert parse_resolv_nameservers(resolv) == ["172.24.0.1", "1.1.1.1"]


def test_relay_script_uses_only_validated_literals():
    script = relay_script("172.24.12.10", 19302, r"C:\Users\Public\r2p-relay-19302.flag")
    assert "172.24.12.10" in script
    assert "19302" in script
    assert "ReceiveTimeout" in script
    assert "r2p-relay-19302.flag" in script
    assert "Invoke-" not in script
    enc = encode_powershell(script)
    assert enc.isascii()
    assert " " not in enc


def test_relay_inactive_on_native_without_spawn():
    spawned: list[list[str]] = []

    def spawn(cmd: list[str]):
        spawned.append(cmd)
        return _LiveProc()

    relay = WslLanRelay(
        flavor=lambda: "none",
        networking_mode=lambda: None,
        local_ips=lambda: ["192.168.1.10"],
        spawn=spawn,
        list_host_ips=lambda: ["192.168.1.10"],
        powershell_exe="powershell.exe",
        ready_wait=0.0,
    )
    msg = relay.start(19302)
    assert msg == ""
    assert relay.active is False
    assert spawned == []


def test_relay_starts_on_wsl2_nat_and_stops():
    spawned: list[list[str]] = []
    proc = _LiveProc()

    def spawn(cmd: list[str]):
        spawned.append(cmd)
        return proc

    relay = WslLanRelay(
        flavor=lambda: "wsl2",
        networking_mode=lambda: "nat",
        local_ips=lambda: ["172.24.12.10"],
        guest_ip=lambda: "172.24.12.10",
        gateway=lambda: "172.24.0.1",
        list_host_ips=lambda: ["192.168.1.5", "172.24.0.1"],
        spawn=spawn,
        powershell_exe="powershell.exe",
        ready_wait=0.0,
    )
    msg = relay.start(19302)
    assert relay.active is True
    assert relay.host_lan_ips == ["192.168.1.5"]
    assert "192.168.1.5:19302" in msg
    assert relay.is_relay_host("172.24.0.1")
    assert spawned and spawned[0][0] == "powershell.exe"
    assert "-EncodedCommand" in spawned[0]
    relay.stop()
    assert relay.active is False
    assert relay.host_lan_ips == []
    assert proc.code == 0

    # Signal handler stops active relays and delegates to previous handler.
    import signal
    from r2p.platform import wsl_nat

    proc2 = _LiveProc()
    relay._spawn = lambda cmd: proc2
    relay.start(19302)
    assert relay.active is True
    delegated: list[int] = []
    saved = wsl_nat._PREV_HANDLERS.get(signal.SIGTERM)
    wsl_nat._PREV_HANDLERS[signal.SIGTERM] = lambda sig, _frame: delegated.append(sig)
    try:
        wsl_nat._relay_signal(signal.SIGTERM, None)
    finally:
        if saved is None:
            wsl_nat._PREV_HANDLERS.pop(signal.SIGTERM, None)
        else:
            wsl_nat._PREV_HANDLERS[signal.SIGTERM] = saved
    assert relay.active is False
    assert proc2.code == 0
    assert delegated == [signal.SIGTERM]


def test_relay_reports_bind_failure():
    relay = WslLanRelay(
        flavor=lambda: "wsl2",
        networking_mode=lambda: "nat",
        local_ips=lambda: ["172.24.12.10"],
        guest_ip=lambda: "172.24.12.10",
        gateway=lambda: "172.24.0.1",
        list_host_ips=lambda: ["192.168.1.5"],
        spawn=lambda cmd: _DeadProc(),
        powershell_exe="powershell.exe",
        ready_wait=0.0,
    )
    msg = relay.start(19302)
    assert relay.active is False
    assert "bind failed" in msg


def test_appcore_presence_uses_host_lan_when_relay_active():
    from pathlib import Path

    from r2p.app_core import AppCore
    from r2p.config import Config
    from r2p.discovery.presence import decode_presence

    root = Path(__file__).resolve().parents[1]
    cfg = Config(
        discovery_backend="lan",
        encodings_path=str(root / "encodings.json"),
        udp_port=19302,
    )
    core = AppCore(cfg)
    try:
        core._public_ip = "203.0.113.9"
        core._wsl_relay.active = True
        core._wsl_relay.host_lan_ips = ["192.168.1.5"]
        core._wsl_relay.relay_hosts = {"172.24.0.1"}
        core._remember_self_endpoints()
        raw = core.get_presence_bytes()
        assert raw is not None
        _inst, endpoints = decode_presence(raw)
        hosts = [h for h, _p in endpoints]
        assert "192.168.1.5" in hosts
        assert "203.0.113.9" in hosts
        assert all(not h.startswith("172.") for h in hosts)
        assert core._wsl_relay.is_relay_host("172.24.0.1")
        assert not core._wsl_relay.is_relay_host("192.168.1.20")
    finally:
        core.stop()
