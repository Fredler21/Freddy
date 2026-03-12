"""File Loader Module — safely reads files with error handling."""

import os
from typing import Optional


class FileLoader:
    """Safely loads files with proper error handling."""

    MAX_FILE_SIZE = 1024 * 1024 * 5  # 5 MB limit for analysis

    @staticmethod
    def load(file_path: str, encode_errors: str = "replace") -> Optional[str]:
        """
        Safely load a file with error handling.
        
        Args:
            file_path: Path to the file
            encode_errors: How to handle encoding errors ('replace', 'ignore', 'strict')
            
        Returns:
            File contents or None if failed
        """
        # Check if file exists
        if not os.path.isfile(file_path):
            return None

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return ""

        if file_size > FileLoader.MAX_FILE_SIZE:
            return FileLoader._load_truncated(file_path, encode_errors)

        # Load file
        try:
            with open(file_path, "r", encoding="utf-8", errors=encode_errors) as f:
                return f.read()
        except PermissionError:
            return f"[!] Permission denied: {file_path}"
        except Exception as e:
            return f"[!] Error reading file: {str(e)}"

    @staticmethod
    def _load_truncated(file_path: str, encode_errors: str) -> str:
        """Load first part of a large file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors=encode_errors) as f:
                content = f.read(FileLoader.MAX_FILE_SIZE)
                content += (
                    "\n\n[...File truncated — exceeded 5MB limit for API analysis...]"
                )
                return content
        except Exception as e:
            return f"[!] Error reading large file: {str(e)}"

    @staticmethod
    def exists(file_path: str) -> bool:
        """Check if a file exists."""
        return os.path.isfile(file_path)
