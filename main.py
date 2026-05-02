#!/usr/bin/env python3
"""
DomainFront Tunnel — Bypass DPI censorship via GAS (Google Apps Script) and Cloudflare Workers.

Run a local HTTP proxy that tunnels all traffic through a Google Apps
Script relay fronted by www.google.com (TLS SNI shows www.google.com
while the encrypted Host header points at script.google.com).
"""

import argparse
import asyncio
import json
import logging
import os
import sys

# Project modules live under ./src — put that folder on sys.path so the
# historical flat imports ("from proxy_server import …") keep working.
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from cert_installer import install_ca, uninstall_ca, is_ca_trusted
from constants import __version__
from lan_utils import log_lan_access
from google_ip_scanner import scan_sync
from logging_utils import configure as configure_logging, print_banner
from mitm import CA_CERT_FILE
from proxy_server import ProxyServer


# ─── ANSI Style Helpers ───────────────────────────────────────────────────
# Lightweight terminal styling with automatic TTY detection.
# Falls back to plain text when stdout is redirected (e.g. logs/files).
# On Windows 10+ we enable Virtual Terminal Processing so that ANSI codes
# (colours, bold, box-drawing) render correctly in cmd.exe / PowerShell.


def _enable_windows_vt() -> bool:
    """Enable Virtual Terminal Processing on the Windows console.

    Returns True if VT mode was successfully enabled (or was already on).
    On non-Windows platforms this is a no-op that returns True.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = wintypes.DWORD(-11)
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = wintypes.DWORD(0x0004)

        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if handle == ctypes.c_void_p(-1).value:          # INVALID_HANDLE_VALUE
            return False

        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False

        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING.value:
            return True                                   # already enabled

        new_mode = wintypes.DWORD(mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING.value)
        return bool(kernel32.SetConsoleMode(handle, new_mode))
    except Exception:
        return False


# Enable Windows VT once at import time, *before* we decide if colour works.
_windows_vt_ok = _enable_windows_vt()
_SUPPORTS_COLOR = (
    hasattr(sys.stdout, "isatty")
    and sys.stdout.isatty()
    and (sys.platform != "win32" or _windows_vt_ok)
)

_ANSI = {
    "reset":    "\033[0m",
    "bold":      "\033[1m",
    "dim":       "\033[2m",
    "underline": "\033[4m",
    "red":       "\033[91m",
    "green":     "\033[92m",
    "yellow":    "\033[93m",
    "blue":      "\033[94m",
    "magenta":   "\033[95m",
    "cyan":      "\033[96m",
    "white":     "\033[97m",
    "gray":      "\033[90m",
}


def _s(text: str, *styles: str) -> str:
    """Wrap *text* with one or more ANSI style tags.

    Usage:  _s("hello", "bold", "cyan")
    When stdout is not a TTY the function returns *text* unchanged.
    """
    if not _SUPPORTS_COLOR:
        return text
    return "".join(_ANSI[s] for s in styles) + text + _ANSI["reset"]


def _box_line(width: int, left: str, right: str, fill: str = "─") -> str:
    """Return a horizontal line segment for the terminal box."""
    inner = width - len(left) - len(right)
    return left + fill * max(inner, 0) + right


def _box(
    title: str = "",
    body: list[str] | None = None,
    width: int = 56,
    color: str = "cyan",
) -> None:
    """Print a rounded-corner info box with an optional *title* and *body* lines.

    Example output::

        ╭──────────────────────────────────────────────────╮
        │  ⚙  Setup Wizard                                │
        ├──────────────────────────────────────────────────┤
        │  Answer a few questions and we'll create a       │
        │  config.json for you.                            │
        ╰──────────────────────────────────────────────────╯
    """
    tl, tr, bl, br = "╭", "╮", "╰", "╯"
    vl, hl, ml = "│", "─", "├"
    # Layout: │  {content}{padding} │
    #         1 + 2 + len(content) + padding + 1 + 1 = width
    #         → padding = width - 5 - len(content)
    _content_w = width - 5

    # Top border
    print(_s(_box_line(width, tl, tr), color))

    # Title row
    if title:
        padding = " " * max(_content_w - len(title), 0)
        print(_s(f"{vl}  {title}{padding} {vl}", color))
        # Separator
        print(_s(_box_line(width, ml, "┤"), color))

    # Body
    if body:
        import re as _re
        _ansi_pat = _re.compile(r"\x1b\[[0-9;]*m")
        for line in body:
            clean = _ansi_pat.sub("", line)
            padding = " " * max(_content_w - len(clean), 0)
            print(f"{vl}  {line}{padding} {vl}")

    # Bottom border
    print(_s(_box_line(width, bl, br), color))


def setup_logging(level_name: str):
    configure_logging(level_name)


_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="domainfront-tunnel",
        description="Local HTTP proxy that relays traffic through Google Apps Script.",
    )
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("DFT_CONFIG", "config.json"),
        help="Path to config file (default: config.json, env: DFT_CONFIG)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override listen port (env: DFT_PORT)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override listen host (env: DFT_HOST)",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        default=None,
        help="Override SOCKS5 listen port (env: DFT_SOCKS5_PORT)",
    )
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Disable the built-in SOCKS5 listener.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (env: DFT_LOG_LEVEL)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--install-cert",
        action="store_true",
        help="Install the MITM CA certificate as a trusted root and exit.",
    )
    parser.add_argument(
        "--uninstall-cert",
        action="store_true",
        help="Remove the MITM CA certificate from trusted roots and exit.",
    )
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Skip the certificate installation check on startup.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan Google IPs to find the fastest reachable one and exit.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Handle cert-only commands before loading config so they can run standalone.
    if args.install_cert or args.uninstall_cert:
        setup_logging("INFO")
        _log = logging.getLogger("Main")

        if args.install_cert:
            _log.info("Installing CA certificate…")
            if not os.path.exists(CA_CERT_FILE):
                from mitm import MITMCertManager
                MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key
            ok = install_ca(CA_CERT_FILE)
            sys.exit(0 if ok else 1)

        _log.info("Removing CA certificate…")
        ok = uninstall_ca(CA_CERT_FILE)
        if ok:
            _log.info("CA certificate removed successfully.")
        else:
            _log.warning("CA certificate removal may have failed. Check logs above.")
        sys.exit(0 if ok else 1)

    config_path = args.config

    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        # ── Config not found ── offer the interactive wizard ─────────
        wizard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")

        print()
        print(_s(f"  ✗  Config file not found: {config_path}", "bold", "yellow"))
        print()

        if os.path.exists(wizard) and sys.stdin.isatty():
            _box(
                title="⚙  Setup Wizard",
                body=[
                    _s("Answer a few questions and we'll create a", "dim"),
                    _s("config.json for you.", "dim"),
                ],
                width=56,
                color="cyan",
            )
            print()
            try:
                prompt = _s("?", "bold", "green") + " " \
                         + _s("Run the interactive setup wizard now?", "bold", "white") \
                         + " " + _s("[Y/n]", "dim") + ": "
                answer = input(prompt).strip().lower()
            except EOFError:
                answer = "n"

            print()

            if answer in ("", "y", "yes"):
                import subprocess
                print(_s("  ▶  Launching setup wizard …", "bold", "cyan"))
                print()
                rc = subprocess.call([sys.executable, wizard])
                if rc != 0:
                    sys.exit(rc)
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                except Exception as e:
                    print()
                    print(_s(f"  ✗  Could not load config after setup: {e}", "bold", "red"))
                    print()
                    sys.exit(1)
            else:
                _box(
                    body=[
                        _s("You can set things up manually:", "white"),
                        "",
                        "  1. Copy " + _s("config.example.json", "bold", "cyan") + " to " + _s("config.json", "bold", "cyan"),
                        "  2. Edit the fields with your own values",
                        "  3. Or run: " + _s("python setup.py", "bold", "green"),
                    ],
                    width=56,
                    color="yellow",
                )
                print()
                sys.exit(1)
        else:
            _box(
                body=[
                    _s("Please create a config file to get started:", "white"),
                    "",
                    "  " + _s("python setup.py", "bold", "green"),
                    "  " + _s("cp config.example.json config.json", "dim"),
                ],
                width=56,
                color="yellow",
            )
            print()
            sys.exit(1)
    except json.JSONDecodeError as e:
        print()
        print(_s(f"  ✗  Invalid JSON in config file: {e}", "bold", "red"))
        print()
        sys.exit(1)

    # Environment variable overrides
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]

    # CLI argument overrides
    if args.port is not None:
        config["listen_port"] = args.port
    elif os.environ.get("DFT_PORT"):
        config["listen_port"] = int(os.environ["DFT_PORT"])

    if args.host is not None:
        config["listen_host"] = args.host
    elif os.environ.get("DFT_HOST"):
        config["listen_host"] = os.environ["DFT_HOST"]

    if args.socks5_port is not None:
        config["socks5_port"] = args.socks5_port
    elif os.environ.get("DFT_SOCKS5_PORT"):
        config["socks5_port"] = int(os.environ["DFT_SOCKS5_PORT"])

    if args.disable_socks5:
        config["socks5_enabled"] = False

    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]

    for key in ("auth_key",):
        if key not in config:
            print()
            print(_s(f"  ✗  Missing required config key: {key}", "bold", "red"))
            print()
            sys.exit(1)

    if config.get("auth_key", "") in _PLACEHOLDER_AUTH_KEYS:
        print()
        print(_s("  ✗  Refusing to start — 'auth_key' is unset or uses a known placeholder.", "bold", "red"))
        print()
        _box(
            body=[
                _s("Pick a long random secret and set it in:", "white"),
                "",
                "  1. " + _s("config.json", "bold", "cyan") + "  →  \"auth_key\" field",
                "  2. " + _s("Code.gs", "bold", "cyan") + "    →  AUTH_KEY constant",
                "",
                _s("Both values must match exactly.", "yellow"),
            ],
            width=56,
            color="red",
        )
        print()
        sys.exit(1)

    # Always Apps Script mode — force-set for backward-compat configs.
    config["mode"] = "apps_script"
    sid = config.get("script_ids") or config.get("script_id")
    if not sid or (isinstance(sid, str) and sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"):
        print()
        print(_s("  ✗  Missing 'script_id' in config.", "bold", "red"))
        print()
        _box(
            body=[
                _s("Deploy the Google Apps Script and paste the Deployment ID:", "white"),
                "",
                "  1. Open " + _s("Code.gs", "bold", "cyan") + " in Google Apps Script",
                "  2. Deploy → New deployment → Web app",
                "  3. Copy the Deployment ID into " + _s("config.json", "bold", "cyan"),
            ],
            width=56,
            color="red",
        )
        print()
        sys.exit(1)

    # ── Google IP Scanner ──────────────────────────────────────────────────
    if args.scan:
        setup_logging("INFO")
        front_domain = config.get("front_domain", "www.google.com")
        _log = logging.getLogger("Main")
        _log.info(f"Scanning Google IPs (fronting domain: {front_domain})")
        ok = scan_sync(front_domain)
        sys.exit(0 if ok else 1)

    setup_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")

    print_banner(__version__)
    log.info("DomainFront Tunnel starting (Apps Script relay)")

    log.info("Apps Script relay : SNI=%s → script.google.com",
             config.get("front_domain", "www.google.com"))
    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        log.info("Script IDs        : %d scripts (sticky per-host)", len(script_ids))
        for i, sid in enumerate(script_ids):
            log.info("  [%d] %s", i + 1, sid)
    else:
        log.info("Script ID         : %s", script_ids)

    # Ensure CA file exists before checking / installing it.
    # MITMCertManager generates ca/ca.crt on first instantiation.
    if not os.path.exists(CA_CERT_FILE):
        from mitm import MITMCertManager
        MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key

    # Auto-install MITM CA if not already trusted
    if not args.no_cert_check:
        if not is_ca_trusted(CA_CERT_FILE):
            log.warning("MITM CA is not trusted — attempting automatic installation…")
            ok = install_ca(CA_CERT_FILE)
            if ok:
                log.info("CA certificate installed. You may need to restart your browser.")
            else:
                log.error(
                    "Auto-install failed. Run with --install-cert (may need admin/sudo) "
                    "or manually install ca/ca.crt as a trusted root CA."
                )
        else:
            log.info("MITM CA is already trusted.")

    # ── LAN sharing configuration ────────────────────────────────────────
    lan_sharing = config.get("lan_sharing", False)
    listen_host = config.get("listen_host", "127.0.0.1")
    if lan_sharing:
        # If LAN sharing is enabled and host is still localhost, change to all interfaces
        if listen_host == "127.0.0.1":
            config["listen_host"] = "0.0.0.0"
            listen_host = "0.0.0.0"
            log.info("LAN sharing enabled — listening on all interfaces")

    # If either explicit LAN sharing is enabled or we bind to all interfaces,
    # print concrete IPv4 addresses users can use on other devices.
    lan_mode = lan_sharing or listen_host in ("0.0.0.0", "::")
    if lan_mode:
        socks_port = config.get("socks5_port", 1080) if config.get("socks5_enabled", True) else None
        log_lan_access(config.get("listen_port", 8080), socks_port)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped")


def _make_exception_handler(log):
    """Return an asyncio exception handler that silences Windows WinError 10054
    noise from connection cleanup (ConnectionResetError in
    _ProactorBasePipeTransport._call_connection_lost), which is harmless but
    verbose on Python/Windows when a remote host force-closes a socket."""
    def handler(loop, context):
        exc = context.get("exception")
        cb  = context.get("handle") or context.get("source_traceback", "")
        if (
            isinstance(exc, ConnectionResetError)
            and "_call_connection_lost" in str(cb)
        ):
            return  # suppress: benign Windows socket cleanup race
        log.error("[asyncio]  %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    return handler


async def _run(config):
    loop = asyncio.get_running_loop()
    _log = logging.getLogger("asyncio")
    loop.set_exception_handler(_make_exception_handler(_log))
    server = ProxyServer(config)
    try:
        await server.start()
    finally:
        await server.stop()


if __name__ == "__main__":
    main()