"""Tool Runner Module — safely executes shell commands and captures output."""

import subprocess
import shutil
from typing import Tuple, Optional
import sys


class ToolRunner:
    """Wrapper for running system commands safely."""

    @staticmethod
    def is_installed(tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return shutil.which(tool_name) is not None

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
