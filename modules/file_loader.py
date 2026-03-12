"""File Loader Module — loads text and PDF documents for Freddy ingestion."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional


class FileLoader:
    """Loads text, markdown, and PDF files with proper error handling."""

    MAX_FILE_SIZE = 1024 * 1024 * 50  # 50 MB limit for PDF ingestion

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def load(file_path: str, encode_errors: str = "replace") -> Optional[str]:
        """Load any supported file (.txt, .md, .pdf) and return its text content."""
        path = Path(file_path)
        if not path.is_file():
            return None

        suffix = path.suffix.lower()
        if suffix == ".pdf":
            return FileLoader._load_pdf(path)
        return FileLoader._load_text(path, encode_errors)

    @staticmethod
    def load_document(path: Path) -> Optional[str]:
        """Load a document from a Path object. Convenience wrapper over load()."""
        return FileLoader.load(str(path))

    @staticmethod
    def exists(file_path: str) -> bool:
        """Check if a file exists."""
        return os.path.isfile(file_path)

    # ------------------------------------------------------------------ #
    # PDF extraction                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _load_pdf(path: Path) -> Optional[str]:
        """Extract text from a PDF using PyMuPDF, falling back to pdfminer.six."""
        text = FileLoader._pdf_via_pymupdf(path)
        if text is not None:
            return FileLoader._normalize_pdf_text(text)

        text = FileLoader._pdf_via_pdfminer(path)
        if text is not None:
            return FileLoader._normalize_pdf_text(text)

        return f"[!] Could not extract text from PDF: {path.name}"

    @staticmethod
    def _pdf_via_pymupdf(path: Path) -> Optional[str]:
        try:
            import fitz  # PyMuPDF

            pages: list[str] = []
            with fitz.open(str(path)) as doc:
                for page in doc:
                    pages.append(page.get_text())
            return "\n".join(pages)
        except ImportError:
            return None
        except Exception:
            return None

    @staticmethod
    def _pdf_via_pdfminer(path: Path) -> Optional[str]:
        try:
            from pdfminer.high_level import extract_text as pdfminer_extract

            return pdfminer_extract(str(path))
        except ImportError:
            return None
        except Exception:
            return None

    @staticmethod
    def _normalize_pdf_text(text: str) -> str:
        """Clean up common PDF extraction artefacts."""
        # Remove null bytes and form-feed characters
        text = text.replace("\x00", "").replace("\f", "\n")
        # Collapse 3+ consecutive newlines to two
        text = re.sub(r"\n{3,}", "\n\n", text)
        # Strip lines that are only whitespace
        lines = [line.rstrip() for line in text.splitlines()]
        return "\n".join(lines).strip()

    # ------------------------------------------------------------------ #
    # Plain text / markdown                                                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _load_text(path: Path, encode_errors: str) -> Optional[str]:
        file_size = path.stat().st_size
        if file_size == 0:
            return ""
        if file_size > FileLoader.MAX_FILE_SIZE:
            return FileLoader._load_truncated(str(path), encode_errors)
        try:
            return path.read_text(encoding="utf-8", errors=encode_errors)
        except PermissionError:
            return f"[!] Permission denied: {path}"
        except Exception as exc:
            return f"[!] Error reading file: {exc}"

    @staticmethod
    def _load_truncated(file_path: str, encode_errors: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors=encode_errors) as fh:
                content = fh.read(FileLoader.MAX_FILE_SIZE)
            return content + "\n\n[...File truncated — exceeded 50 MB limit for ingestion...]"
        except Exception as exc:
            return f"[!] Error reading large file: {exc}"

