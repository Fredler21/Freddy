from __future__ import annotations

"""Platform-aware guidance helpers for Freddy."""

import os
import platform


LINUX_ONLY_COMMANDS = {"ports", "audit"}


def current_platform() -> str:
    """Return a normalized platform label."""
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
            return "wsl"
        return "linux"
    return system or "unknown"


def is_windows_like() -> bool:
    """Return True for native Windows terminals."""
    return current_platform() == "windows"


def is_linux_like() -> bool:
    """Return True for Linux and WSL environments."""
    return current_platform() in {"linux", "wsl"}


def linux_only_message(command_name: str) -> str:
    """Return a standard message for Linux-native commands."""
    return (
        f"[!] '{command_name}' is a Linux-native workflow and is not fully supported from a native Windows terminal. "
        "Run Freddy inside Linux or WSL for local host inspection commands such as ports, audit, ufw, iptables, and systemctl-based analysis."
    )


def install_hint(tool_name: str) -> str:
    """Return a platform-aware install hint for a missing external tool."""
    platform_name = current_platform()
    if platform_name == "windows":
        return (
            f"Install '{tool_name}' and ensure it is available on PATH, or run Freddy inside WSL/Linux where that tool is commonly available."
        )
    if platform_name == "macos":
        return f"Install '{tool_name}' with Homebrew or another package manager, then ensure it is on PATH."
    return f"Install '{tool_name}' with your system package manager and ensure it is on PATH."
