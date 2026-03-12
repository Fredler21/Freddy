"""Tool Runner Module — safely executes shell commands and captures output."""

import os
import subprocess
import shutil
from typing import Tuple, Optional


class ToolRunner:
    """Wrapper for running system commands safely."""

    WINDOWS_TOOL_CANDIDATES = {
        "nmap": [
            r"{ProgramFiles}\Nmap\nmap.exe",
            r"{ProgramFiles(x86)}\Nmap\nmap.exe",
            r"{ChocolateyInstall}\bin\nmap.exe",
            r"{USERPROFILE}\scoop\shims\nmap.exe",
        ],
        "openssl": [
            r"{ProgramFiles}\OpenSSL-Win64\bin\openssl.exe",
            r"{ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe",
            r"{ProgramFiles}\Git\usr\bin\openssl.exe",
            r"{ProgramFiles}\Git\mingw64\bin\openssl.exe",
            r"{ChocolateyInstall}\bin\openssl.exe",
            r"{USERPROFILE}\scoop\shims\openssl.exe",
        ],
        "dig": [
            r"{ProgramFiles}\ISC BIND 9\bin\dig.exe",
            r"{ProgramFiles(x86)}\ISC BIND 9\bin\dig.exe",
            r"{ChocolateyInstall}\bin\dig.exe",
            r"{USERPROFILE}\scoop\shims\dig.exe",
        ],
        "host": [
            r"{ProgramFiles}\ISC BIND 9\bin\host.exe",
            r"{ProgramFiles(x86)}\ISC BIND 9\bin\host.exe",
            r"{ChocolateyInstall}\bin\host.exe",
            r"{USERPROFILE}\scoop\shims\host.exe",
        ],
        "whois": [
            r"{ProgramFiles}\Sysinternals Suite\whois.exe",
            r"{ProgramFiles(x86)}\Sysinternals Suite\whois.exe",
            r"{ChocolateyInstall}\bin\whois.exe",
            r"{USERPROFILE}\scoop\shims\whois.exe",
        ],
        "curl": [
            r"{SystemRoot}\System32\curl.exe",
            r"{ProgramFiles}\Git\mingw64\bin\curl.exe",
            r"{ProgramFiles}\Git\usr\bin\curl.exe",
            r"{ChocolateyInstall}\bin\curl.exe",
            r"{USERPROFILE}\scoop\shims\curl.exe",
        ],
        "whatweb": [
            r"{ChocolateyInstall}\bin\whatweb.bat",
            r"{ChocolateyInstall}\bin\whatweb.exe",
            r"{USERPROFILE}\scoop\shims\whatweb.cmd",
        ],
        "nikto": [
            r"{ChocolateyInstall}\bin\nikto.bat",
            r"{ChocolateyInstall}\bin\nikto.cmd",
            r"{USERPROFILE}\scoop\shims\nikto.cmd",
        ],
        "nslookup": [
            r"{SystemRoot}\System32\nslookup.exe",
        ],
    }

    @staticmethod
    def is_installed(tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return ToolRunner.resolve_tool(tool_name) is not None

    @staticmethod
    def resolve_tool(tool_name: str) -> Optional[str]:
        """Resolve a tool from PATH or common Windows install locations."""
        resolved = shutil.which(tool_name)
        if resolved:
            return resolved

        if os.name != "nt":
            return None

        for candidate in ToolRunner.WINDOWS_TOOL_CANDIDATES.get(tool_name.lower(), []):
            expanded = ToolRunner._expand_windows_candidate(candidate)
            if expanded and os.path.exists(expanded):
                return expanded
        return None

    @staticmethod
    def build_command(tool_name: str, *args: str) -> list[str]:
        """Build a command list using a resolved executable path when possible."""
        executable = ToolRunner.resolve_tool(tool_name) or tool_name
        return [executable, *args]

    @staticmethod
    def _expand_windows_candidate(candidate: str) -> Optional[str]:
        values = {
            "ProgramFiles": os.environ.get("ProgramFiles", ""),
            "ProgramFiles(x86)": os.environ.get("ProgramFiles(x86)", ""),
            "ChocolateyInstall": os.environ.get("ChocolateyInstall", ""),
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        }
        try:
            expanded = candidate.format(**values)
        except KeyError:
            return None
        return expanded if expanded and not expanded.startswith("\\") else None

    @staticmethod
    def run(
        command: list,
        timeout: int = 60,
        silent_fail: bool = False,
    ) -> Tuple[str, str, int]:
        """
        Execute a command safely and return stdout, stderr, and return code.
        
        Args:
            command: List of command arguments (e.g., ["nmap", "-sV", "example.com"])
            timeout: Timeout in seconds
            silent_fail: If True, don't raise on command failure
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout} seconds", -1
        except FileNotFoundError:
            return "", f"Command not found: {command[0]}", -1
        except OSError as e:
            return "", f"Failed to execute: {str(e)}", -1
        except Exception as e:
            return "", f"Unexpected error: {str(e)}", -1

    @staticmethod
    def run_with_sudo(
        command: list,
        timeout: int = 60,
    ) -> Tuple[str, str, int]:
        """
        Execute a command with sudo (requires password-less sudo or interactive prompt).
        
        Args:
            command: List of command arguments
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        sudo_command = ["sudo"] + command
        return ToolRunner.run(sudo_command, timeout=timeout)

    @staticmethod
    def run_shell(
        command: str,
        timeout: int = 60,
    ) -> Tuple[str, str, int]:
        """
        Execute a raw shell command string.
        
        Args:
            command: Shell command as string
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout} seconds", -1
        except Exception as e:
            return "", f"Failed to execute: {str(e)}", -1
