"""WSL2 NAT: advertise the Windows LAN IPv4 and relay inbound UDP.

Native Linux, WSL1, and WSL2 mirrored mode do not use this path.
"""

from __future__ import annotations

import atexit
import base64
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping

from r2p.discovery.presence import is_ipv4, is_private_ipv4, shares_lan

# Hyper-V vSwitch for default WSL2 NAT is typically 172.16.0.0/12.
_POWERSHELL_CANDIDATES = (
    "powershell.exe",
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe",
)


def wsl_flavor(
    environ: Mapping[str, str] | None = None,
    release: str | None = None,
) -> str:
    """Return 'wsl2', 'wsl1', or 'none'."""
    env = os.environ if environ is None else environ
    if release is None:
        release = os.uname().release if hasattr(os, "uname") else ""
    rel = release.lower()
    named = bool(env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"))
    if "wsl2" in rel or "microsoft-standard" in rel:
        return "wsl2"
    if "microsoft" in rel:
        return "wsl1"
    if named:
        return "wsl2"
    return "none"


def is_hyperv_virtual_ipv4(host: str) -> bool:
    if not is_ipv4(host):
        return False
    o = [int(p) for p in host.split(".")]
    return o[0] == 172 and 16 <= o[1] <= 31


def parse_ipv4_lines(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        token = raw.strip().strip("[]")
        if not is_ipv4(token):
            continue
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def parse_default_gateway(route_text: str) -> str | None:
    """Parse Linux /proc/net/route text. Destination 00000000 is the default."""
    lines = route_text.splitlines()
    if not lines:
        return None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[1] != "00000000":
            continue
        gw_hex = parts[2]
        if len(gw_hex) != 8:
            continue
        try:
            raw = bytes.fromhex(gw_hex)
        except ValueError:
            continue
        ip = f"{raw[3]}.{raw[2]}.{raw[1]}.{raw[0]}"
        if is_ipv4(ip) and ip != "0.0.0.0":
            return ip
    return None


def parse_resolv_nameservers(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and is_ipv4(parts[1]):
            out.append(parts[1])
    return out


def is_wsl_vswitch_ip(ip: str, guest_ip: str | None, gateway: str | None) -> bool:
    if not is_ipv4(ip):
        return False
    if gateway and ip == gateway:
        return True
    if guest_ip and ip == guest_ip:
        return True
    if guest_ip and is_private_ipv4(guest_ip) and shares_lan(ip, {guest_ip}):
        return True
    if (
        guest_ip
        and is_hyperv_virtual_ipv4(guest_ip)
        and is_hyperv_virtual_ipv4(ip)
        and ip.split(".")[:2] == guest_ip.split(".")[:2]
    ):
        return True
    return False


def filter_host_lan_ips(
    windows_ips: list[str],
    guest_ip: str | None,
    gateway: str | None,
) -> list[str]:
    """Keep Windows IPv4s that a LAN peer can use; drop vSwitch / loopback."""
    out: list[str] = []
    seen: set[str] = set()
    for ip in windows_ips:
        if not is_ipv4(ip) or ip in seen:
            continue
        if ip.startswith("127.") or ip.startswith("169.254.") or ip == "0.0.0.0":
            continue
        if is_wsl_vswitch_ip(ip, guest_ip, gateway):
            continue
        seen.add(ip)
        out.append(ip)
    return out


def should_start_relay(
    flavor: str,
    networking_mode: str | None,
    local_ips: list[str],
) -> bool:
    """True only for WSL2 NAT with no already-LAN-reachable IPv4."""
    if flavor != "wsl2":
        return False
    mode = (networking_mode or "").strip().lower()
    if mode == "mirrored":
        return False
    usable = [
        ip
        for ip in local_ips
        if is_ipv4(ip) and not ip.startswith("127.") and ip != "0.0.0.0"
    ]
    real_lan = [ip for ip in usable if not is_hyperv_virtual_ipv4(ip)]
    if real_lan:
        # Guest already has a host-like IPv4 (mirrored / bridged). Do not bind twice.
        return False
    if mode == "nat":
        return True
    return bool(usable)


def relay_script(guest_ip: str, port: int, heartbeat_path: str) -> str:
    """PowerShell UDP inbound relay. guest_ip, port, path must already be validated."""
    hb = heartbeat_path.replace("'", "''")
    return (
        "$ErrorActionPreference = 'Continue'\n"
        f"$wsl = [Net.IPAddress]::Parse('{guest_ip}')\n"
        f"$port = {int(port)}\n"
        f"$hb = '{hb}'\n"
        "$udp = New-Object Net.Sockets.UdpClient\n"
        "$udp.Client.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::Any, $port)))\n"
        "$udp.Client.ReceiveTimeout = 2000\n"
        "$dst = New-Object Net.IPEndPoint ($wsl, $port)\n"
        "while ($true) {\n"
        "  if (-not (Test-Path $hb)) { break }\n"
        "  $age = (Get-Date) - (Get-Item $hb).LastWriteTime\n"
        "  if ($age.TotalSeconds -gt 5) { break }\n"
        "  $from = New-Object Net.IPEndPoint ([Net.IPAddress]::Any, 0)\n"
        "  try {\n"
        "    $bytes = $udp.Receive([ref]$from)\n"
        "  } catch {\n"
        "    continue\n"
        "  }\n"
        "  if ($from.Address.Equals($wsl)) { continue }\n"
        "  [void]$udp.Send($bytes, $bytes.Length, $dst)\n"
        "}\n"
    )


def encode_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


class WslLanRelay:
    """Optional Windows UDP relay. Inactive on every non-WSL2-NAT host."""

    def __init__(
        self,
        *,
        list_host_ips: Callable[[], list[str]] | None = None,
        spawn: Callable[[list[str]], subprocess.Popen] | None = None,
        powershell_exe: str | None = None,
        networking_mode: Callable[[], str | None] | None = None,
        local_ips: Callable[[], list[str]] | None = None,
        guest_ip: Callable[[], str | None] | None = None,
        gateway: Callable[[], str | None] | None = None,
        flavor: Callable[[], str] | None = None,
        ready_wait: float = 0.25,
    ) -> None:
        self._list_host_ips = list_host_ips or self._query_windows_ipv4
        self._spawn = spawn or _spawn_hidden
        self._powershell_exe = powershell_exe
        self._networking_mode = networking_mode or _wslinfo_networking_mode
        self._local_ips = local_ips
        self._guest_ip_fn = guest_ip
        self._gateway_fn = gateway
        self._flavor_fn = flavor or (lambda: wsl_flavor())
        self._ready_wait = max(0.0, float(ready_wait))
        self._proc: subprocess.Popen | None = None
        self._wanted = False
        self.active = False
        self.host_lan_ips: list[str] = []
        self.relay_hosts: set[str] = set()
        self.guest_ip: str | None = None
        self.listen_port = 0
        self.status = ""
        self._hb_linux: str | None = None

    def install_hooks(self) -> None:
        """Install atexit and SIGTERM/SIGINT cleanup hooks (call on main thread)."""
        global _ATEXIT_INSTALLED, _SIGNAL_HOOKS_INSTALLED
        if self._flavor_fn() != "wsl2":
            return
        if self not in _RELAYS:
            _RELAYS.append(self)
        if not _ATEXIT_INSTALLED:
            atexit.register(_stop_all_relays)
            _ATEXIT_INSTALLED = True
        if not _SIGNAL_HOOKS_INSTALLED:
            installed = False
            for sig in (signal.SIGTERM, signal.SIGINT):
                try:
                    prev = signal.getsignal(sig)
                    signal.signal(sig, _relay_signal)
                    _PREV_HANDLERS[sig] = prev
                    installed = True
                except (ValueError, OSError):
                    pass
            if installed:
                _SIGNAL_HOOKS_INSTALLED = True

    def is_relay_host(self, host: str) -> bool:
        return host in self.relay_hosts

    def beat(self) -> None:
        path = self._hb_linux
        if not path:
            return
        try:
            with open(path, "w", encoding="ascii") as fh:
                fh.write(str(time.time()))
        except OSError:
            pass

    def start(self, listen_port: int) -> str:
        """Start relay if this is WSL2 NAT. Return a status string (may be empty)."""
        self.stop()
        self._wanted = False
        port = int(listen_port)
        if not (1 <= port <= 65535):
            return ""
        flavor = self._flavor_fn()
        locals_ = self._local_ips() if self._local_ips else _guest_local_ips()
        mode = self._networking_mode()
        if not should_start_relay(flavor, mode, locals_):
            return ""
        guest = self._guest_ip_fn() if self._guest_ip_fn else _pick_guest_ip(locals_)
        if not guest or not is_ipv4(guest):
            self.status = "WSL NAT: no guest IPv4"
            return self.status
        gw = self._gateway_fn() if self._gateway_fn else _read_gateway()
        try:
            windows_ips = self._list_host_ips()
        except (OSError, subprocess.SubprocessError, TimeoutError):
            self.status = "WSL NAT: host IP query failed"
            return self.status
        lan = filter_host_lan_ips(windows_ips, guest, gw)
        if not lan:
            self.status = "WSL NAT: no host LAN IPv4"
            return self.status
        exe = self._powershell_exe or _find_powershell()
        if not exe:
            self.status = "WSL NAT: no powershell.exe"
            return self.status
        hb_linux, hb_win = heartbeat_paths(port)
        self._hb_linux = hb_linux
        try:
            with open(hb_linux, "w", encoding="ascii") as fh:
                fh.write(str(time.time()))
        except OSError:
            self.status = "WSL NAT: heartbeat failed"
            return self.status
        self.install_hooks()
        script = relay_script(guest, port, hb_win)
        cmd = [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encode_powershell(script),
        ]
        try:
            proc = self._spawn(cmd)
        except OSError:
            self.status = "WSL NAT: relay spawn failed"
            self.stop()
            self.status = "WSL NAT: relay spawn failed"
            return self.status
        if self._ready_wait:
            time.sleep(self._ready_wait)
        if proc.poll() is not None:
            self.stop()
            self.status = "WSL NAT: relay bind failed"
            return self.status
        self._proc = proc
        self._wanted = True
        self.active = True
        self.host_lan_ips = lan
        self.guest_ip = guest
        self.listen_port = port
        self.relay_hosts = set()
        if gw:
            self.relay_hosts.add(gw)
        self.relay_hosts.add(guest)
        for ip in windows_ips:
            if is_wsl_vswitch_ip(ip, guest, gw):
                self.relay_hosts.add(ip)
        shown = lan[0]
        self.status = f"WSL NAT relay {shown}:{port}"
        return self.status

    def stop(self) -> None:
        self._wanted = False
        self.active = False
        self.host_lan_ips = []
        self.relay_hosts = set()
        self.guest_ip = None
        self.listen_port = 0
        self.status = ""
        hb = self._hb_linux
        self._hb_linux = None
        if hb:
            try:
                os.remove(hb)
            except OSError:
                pass
        if self in _RELAYS:
            _RELAYS.remove(self)
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            proc.terminate()
        except OSError:
            return
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                pass
        except OSError:
            pass

    def tick(self, listen_port: int) -> str:
        """Restart a wanted relay that exited. Return new status or empty."""
        if not self._wanted:
            return ""
        if self._proc is not None and self._proc.poll() is None:
            return ""
        return self.start(listen_port)

    def _query_windows_ipv4(self) -> list[str]:
        exe = self._powershell_exe or _find_powershell()
        if not exe:
            return []
        cmd = [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty IPAddress",
        ]
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return parse_ipv4_lines(completed.stdout or "")


def _find_powershell() -> str | None:
    for cand in _POWERSHELL_CANDIDATES:
        if os.path.sep in cand:
            if os.path.isfile(cand):
                return cand
            continue
        found = shutil.which(cand)
        if found:
            return found
    return None


def _wslinfo_networking_mode() -> str | None:
    exe = shutil.which("wslinfo")
    if not exe:
        return None
    try:
        completed = subprocess.run(
            [exe, "--networking-mode"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    mode = (completed.stdout or "").strip().split()
    if not mode:
        return None
    return mode[0].lower()


def _guest_local_ips() -> list[str]:
    from r2p.discovery.presence import local_ipv4_addresses

    return local_ipv4_addresses()


def _pick_guest_ip(local_ips: list[str]) -> str | None:
    from r2p.discovery.presence import primary_ipv4

    primary = primary_ipv4()
    if primary:
        return primary
    for ip in local_ips:
        if is_ipv4(ip) and not ip.startswith("127."):
            return ip
    return None


def _read_gateway() -> str | None:
    try:
        text = _read_text("/proc/net/route")
    except OSError:
        text = ""
    gw = parse_default_gateway(text) if text else None
    if gw:
        return gw
    try:
        resolv = _read_text("/etc/resolv.conf")
    except OSError:
        return None
    names = parse_resolv_nameservers(resolv)
    return names[0] if names else None


def heartbeat_paths(port: int) -> tuple[str, str]:
    name = f"r2p-relay-{int(port)}.flag"
    public = "/mnt/c/Users/Public"
    if os.path.isdir(public):
        linux = os.path.join(public, name)
        return linux, f"C:\\Users\\Public\\{name}"
    linux = os.path.join("/tmp", name)
    return linux, linux


_ATEXIT_INSTALLED = False
_SIGNAL_HOOKS_INSTALLED = False
_PREV_HANDLERS: dict[int, object] = {}
_RELAYS: list[WslLanRelay] = []


def _stop_all_relays() -> None:
    for relay in list(_RELAYS):
        relay.stop()


def _relay_signal(signum, frame) -> None:
    _stop_all_relays()
    prev = _PREV_HANDLERS.get(signum)
    if callable(prev):
        prev(signum, frame)
    elif prev in (None, signal.SIG_DFL):
        try:
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        except OSError:
            pass


def _spawn_hidden(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
