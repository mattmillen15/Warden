#!/usr/bin/env python3
"""Warden service controller (cross-platform).

- macOS: launchd LaunchAgent (persistent user service)
- Linux/Windows: portable background service mode managed by this script (PID + logs)
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

LABEL = "com.warden.portal"
ROOT_DIR = Path(__file__).resolve().parent
PORTAL_DIR = ROOT_DIR / "portal"
APP_FILE = PORTAL_DIR / "app.py"
REQ_FILE = PORTAL_DIR / "requirements.txt"
LOG_DIR = ROOT_DIR / "logs"
OUT_LOG = LOG_DIR / "warden.out.log"
ERR_LOG = LOG_DIR / "warden.err.log"
STATE_FILE = LOG_DIR / "warden.service.json"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"

WINDOWS_DETACHED_PROCESS = 0x00000008
WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
WINDOWS_CREATE_NO_WINDOW = 0x08000000


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _is_windows() -> bool:
    return os.name == "nt"


def _venv_python_path() -> Path:
    candidates = [
        PORTAL_DIR / ".venv" / "bin" / "python",
        PORTAL_DIR / ".venv" / "Scripts" / "python.exe",
        PORTAL_DIR / ".venv" / "Scripts" / "python",
    ]
    for p in candidates:
        if p.exists():
            return p
    # Default to POSIX path in error messages if venv not found yet.
    return candidates[0]


def _venv_pip_path() -> Path:
    candidates = [
        PORTAL_DIR / ".venv" / "bin" / "pip",
        PORTAL_DIR / ".venv" / "Scripts" / "pip.exe",
        PORTAL_DIR / ".venv" / "Scripts" / "pip",
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def _launchd_target() -> str:
    return f"gui/{os.getuid()}"


def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{err}")
    return result


def _ensure_paths() -> None:
    if not APP_FILE.exists():
        raise RuntimeError(f"Missing portal app: {APP_FILE}")
    venv_python = _venv_python_path()
    if not venv_python.exists():
        raise RuntimeError(f"Missing venv python: {venv_python}. Run setup first.")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if _is_macos():
        PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)


def _bootstrap_environment(upgrade_pip: bool = True) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not APP_FILE.exists():
        raise RuntimeError(f"Missing portal app: {APP_FILE}")
    if not REQ_FILE.exists():
        raise RuntimeError(f"Missing requirements file: {REQ_FILE}")

    if not _venv_python_path().exists():
        print(f"Creating virtual environment at {PORTAL_DIR / '.venv'}")
        _run([sys.executable, "-m", "venv", str(PORTAL_DIR / ".venv")], check=True)

    venv_python = _venv_python_path()
    pip_cmd = [str(venv_python), "-m", "pip"]
    if upgrade_pip:
        print("Upgrading pip...")
        _run(pip_cmd + ["install", "--upgrade", "pip"], check=True)
    print("Installing Warden dependencies...")
    _run(pip_cmd + ["install", "-r", str(REQ_FILE)], check=True)


def _tail_file(path: Path, lines: int) -> str:
    if not path.exists():
        return ""
    try:
        with path.open("rb") as f:
            data = f.read().splitlines()
        return b"\n".join(data[-lines:]).decode("utf-8", errors="replace")
    except Exception:
        try:
            return path.read_text(errors="replace")
        except Exception:
            return ""


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text())
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2) + "\n")


def _clear_state() -> None:
    try:
        STATE_FILE.unlink()
    except FileNotFoundError:
        pass


def _portable_service_config() -> dict[str, Any]:
    state = _load_state()
    return {
        "mode": "portable",
        "host": str(state.get("host") or "127.0.0.1"),
        "port": int(state.get("port") or 5000),
        "pid": state.get("pid"),
        "started_at": state.get("started_at"),
    }


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if _is_windows():
        res = _run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], check=False)
        text = (res.stdout or "").strip()
        if not text or text.startswith("INFO:"):
            return False
        return f'"{pid}"' in text or str(pid) in text
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _portable_install(host: str, port: int) -> None:
    state = _load_state()
    state.update({"mode": "portable", "host": host, "port": int(port)})
    _save_state(state)


def _portable_start(host: str | None = None, port: int | None = None) -> None:
    _ensure_paths()
    state = _load_state()
    cfg_host = str(host or state.get("host") or "127.0.0.1")
    cfg_port = int(port or state.get("port") or 5000)

    existing_pid = state.get("pid")
    try:
        existing_pid = int(existing_pid) if existing_pid is not None else None
    except Exception:
        existing_pid = None
    if existing_pid and _pid_running(existing_pid):
        print(f"Warden already running (pid: {existing_pid}) at http://{cfg_host}:{cfg_port}")
        return

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["WARDEN_HOST"] = cfg_host
    env["WARDEN_PORT"] = str(cfg_port)
    env["WARDEN_DEBUG"] = "0"

    venv_python = _venv_python_path()
    stdin_f = open(os.devnull, "rb")
    out_f = open(OUT_LOG, "ab")
    err_f = open(ERR_LOG, "ab")

    popen_kwargs: dict[str, Any] = {
        "cwd": str(PORTAL_DIR),
        "env": env,
        "stdin": stdin_f,
        "stdout": out_f,
        "stderr": err_f,
        "close_fds": True,
    }
    if _is_windows():
        popen_kwargs["creationflags"] = (
            WINDOWS_DETACHED_PROCESS | WINDOWS_CREATE_NEW_PROCESS_GROUP | WINDOWS_CREATE_NO_WINDOW
        )
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen([str(venv_python), str(APP_FILE)], **popen_kwargs)
    finally:
        stdin_f.close()
        out_f.close()
        err_f.close()

    time.sleep(0.5)
    state.update(
        {
            "mode": "portable",
            "host": cfg_host,
            "port": cfg_port,
            "pid": proc.pid,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
    )
    _save_state(state)
    print(f"Warden started at http://{cfg_host}:{cfg_port} (pid: {proc.pid})")


def _portable_stop() -> None:
    state = _load_state()
    pid = state.get("pid")
    try:
        pid = int(pid)
    except Exception:
        pid = None

    if not pid or not _pid_running(pid):
        print("Warden not running.")
        state.pop("pid", None)
        _save_state(state) if state else _clear_state()
        return

    if _is_windows():
        _run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.time() + 5
        while time.time() < deadline and _pid_running(pid):
            time.sleep(0.15)
        if _pid_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

    if _pid_running(pid):
        print(f"Warden stop requested but process {pid} is still running.")
    else:
        print("Warden stopped.")
        state.pop("pid", None)
        state["stopped_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _save_state(state)


def _portable_status() -> None:
    state = _load_state()
    host = str(state.get("host") or "127.0.0.1")
    port = int(state.get("port") or 5000)
    pid = state.get("pid")
    try:
        pid_int = int(pid) if pid is not None else None
    except Exception:
        pid_int = None

    if pid_int and _pid_running(pid_int):
        print(f"Warden status: running (pid: {pid_int})")
        print(f"URL: http://{host}:{port}")
        print(f"Logs: {OUT_LOG} | {ERR_LOG}")
        return

    print("Warden status: not running")
    print(f"Configured URL: http://{host}:{port}")
    if STATE_FILE.exists():
        print(f"Portable service config: {STATE_FILE}")


def _portable_uninstall() -> None:
    _portable_stop()
    _clear_state()
    print("Portable service configuration removed.")


def _write_plist(host: str, port: int) -> None:
    venv_python = _venv_python_path()
    data = {
        "Label": LABEL,
        "ProgramArguments": [str(venv_python), str(APP_FILE)],
        "WorkingDirectory": str(PORTAL_DIR),
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(OUT_LOG),
        "StandardErrorPath": str(ERR_LOG),
        "EnvironmentVariables": {
            "PYTHONUNBUFFERED": "1",
            "WARDEN_HOST": host,
            "WARDEN_PORT": str(port),
            "WARDEN_DEBUG": "0",
        },
    }
    with PLIST_PATH.open("wb") as f:
        plistlib.dump(data, f, sort_keys=False)


def _is_loaded() -> tuple[bool, str]:
    target = f"{_launchd_target()}/{LABEL}"
    res = _run(["launchctl", "print", target], check=False)
    text = (res.stdout or "") + "\n" + (res.stderr or "")
    return res.returncode == 0, text


def _read_port_from_plist() -> int:
    if not PLIST_PATH.exists():
        return 5000
    try:
        with PLIST_PATH.open("rb") as f:
            data = plistlib.load(f)
        env = data.get("EnvironmentVariables", {}) or {}
        return int(env.get("WARDEN_PORT", "5000"))
    except Exception:
        return 5000


def _mac_install(host: str, port: int) -> None:
    _ensure_paths()
    _write_plist(host, port)
    print(f"Wrote launch agent: {PLIST_PATH}")


def _mac_start() -> None:
    if not PLIST_PATH.exists():
        raise RuntimeError(
            f"Launch agent not installed: {PLIST_PATH}. Run python3 warden.py setup --start or python3 warden.py install --start"
        )
    target = _launchd_target()
    _run(["launchctl", "bootout", target, str(PLIST_PATH)], check=False)
    res = _run(["launchctl", "bootstrap", target, str(PLIST_PATH)], check=False)
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(f"Failed to start launch agent: {err}")
    _run(["launchctl", "kickstart", "-k", f"{target}/{LABEL}"], check=False)
    print(f"Warden started at http://127.0.0.1:{_read_port_from_plist()}")


def _mac_stop() -> None:
    if not PLIST_PATH.exists():
        print("Launch agent not installed.")
        return
    res = _run(["launchctl", "bootout", _launchd_target(), str(PLIST_PATH)], check=False)
    if res.returncode == 0:
        print("Warden stopped.")
    else:
        print("Warden stop returned non-zero (service may already be stopped).")


def _mac_status() -> None:
    loaded, text = _is_loaded()
    if not loaded:
        print("Warden status: not running")
        if PLIST_PATH.exists():
            print(f"Launch agent installed: {PLIST_PATH}")
        else:
            print("Launch agent not installed.")
        return

    state = "unknown"
    pid = "?"
    m_state = re.search(r"state\s*=\s*(\w+)", text)
    if m_state:
        state = m_state.group(1)
    m_pid = re.search(r"\bpid\s*=\s*(\d+)", text)
    if m_pid:
        pid = m_pid.group(1)
    port = _read_port_from_plist()
    print(f"Warden status: {state} (pid: {pid})")
    print(f"URL: http://127.0.0.1:{port}")
    print(f"Logs: {OUT_LOG} | {ERR_LOG}")


def _mac_uninstall() -> None:
    _mac_stop()
    if PLIST_PATH.exists():
        PLIST_PATH.unlink()
        print(f"Removed {PLIST_PATH}")
    else:
        print("Launch agent already removed.")


def _mode() -> str:
    return "launchd" if _is_macos() else "portable"


def cmd_install(args: argparse.Namespace) -> int:
    if _mode() == "launchd":
        _mac_install(args.host, args.port)
    else:
        _ensure_paths()
        _portable_install(args.host, args.port)
        print(f"Installed portable service config: {STATE_FILE}")
    if args.start:
        return cmd_start(args)
    print("Install complete. Start with: python3 warden.py start")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    _bootstrap_environment(upgrade_pip=not bool(args.skip_pip_upgrade))
    install_args = argparse.Namespace(host=args.host, port=args.port, start=bool(args.start))
    cmd_install(install_args)
    if not args.start:
        print("")
        print("Setup complete. Start with: python3 warden.py start")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    if _mode() == "launchd":
        _mac_start()
    else:
        _portable_start()
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if _mode() == "launchd":
        _mac_stop()
    else:
        _portable_stop()
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    cmd_stop(args)
    return cmd_start(args)


def cmd_status(args: argparse.Namespace) -> int:
    if _mode() == "launchd":
        _mac_status()
    else:
        _portable_status()
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    n = max(1, int(args.lines))
    print(f"== {OUT_LOG} ==")
    out = _tail_file(OUT_LOG, n)
    if out:
        print(out.rstrip())
    print(f"\n== {ERR_LOG} ==")
    err = _tail_file(ERR_LOG, n)
    if err:
        print(err.rstrip())
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    if _mode() == "launchd":
        _mac_uninstall()
    else:
        _portable_uninstall()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    _ensure_paths()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["WARDEN_HOST"] = str(args.host)
    env["WARDEN_PORT"] = str(args.port)
    env["WARDEN_DEBUG"] = "1" if args.debug else "0"
    venv_python = _venv_python_path()
    print(f"Running Warden in foreground at http://{args.host}:{args.port}")
    proc = subprocess.run([str(venv_python), str(APP_FILE)], cwd=str(PORTAL_DIR), env=env)
    return int(proc.returncode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Warden service manager")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Create venv, install deps, install service config")
    p_setup.add_argument("--host", default="127.0.0.1")
    p_setup.add_argument("--port", type=int, default=5000)
    p_setup.add_argument("--start", action="store_true", default=True, help="Start service after setup (default)")
    p_setup.add_argument("--no-start", dest="start", action="store_false", help="Do not start service after setup")
    p_setup.add_argument("--skip-pip-upgrade", action="store_true", help="Skip pip self-upgrade")
    p_setup.set_defaults(func=cmd_setup)

    p_install = sub.add_parser("install", help="Install service configuration")
    p_install.add_argument("--host", default="127.0.0.1")
    p_install.add_argument("--port", type=int, default=5000)
    p_install.add_argument("--start", action="store_true", help="Start service after install")
    p_install.set_defaults(func=cmd_install)

    p_start = sub.add_parser("start", help="Start service")
    p_start.set_defaults(func=cmd_start)

    p_stop = sub.add_parser("stop", help="Stop service")
    p_stop.set_defaults(func=cmd_stop)

    p_restart = sub.add_parser("restart", help="Restart service")
    p_restart.set_defaults(func=cmd_restart)

    p_status = sub.add_parser("status", help="Show service status")
    p_status.set_defaults(func=cmd_status)

    p_logs = sub.add_parser("logs", help="Show service logs")
    p_logs.add_argument("--lines", type=int, default=60)
    p_logs.set_defaults(func=cmd_logs)

    p_uninstall = sub.add_parser("uninstall", help="Uninstall service configuration")
    p_uninstall.set_defaults(func=cmd_uninstall)

    p_run = sub.add_parser("run", help="Run portal in foreground (manual/debug)")
    p_run.add_argument("--host", default="127.0.0.1")
    p_run.add_argument("--port", type=int, default=5000)
    p_run.add_argument("--debug", action="store_true")
    p_run.set_defaults(func=cmd_run)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
