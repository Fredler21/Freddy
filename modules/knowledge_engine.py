from __future__ import annotations

"""Knowledge retrieval engine for Freddy."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import hashlib
import re

import chromadb
from chromadb.api.models.Collection import Collection
from sentence_transformers import SentenceTransformer

from config import BASE_DIR, VECTOR_DB_DIR, EMBEDDING_MODEL, KNOWLEDGE_DIR, VULNERABILITY_DIR


@dataclass(slots=True)
class KnowledgeMatch:
    """A retrieved knowledge chunk."""

    document: str
    source: str
    category: str
    score: float
    title: str
    slug: str


class KnowledgeEngine:
    """Indexes and queries Freddy's local cybersecurity knowledge base."""

    COLLECTION_NAME = "freddy_knowledge"
    CHUNK_SIZE = 900
    CHUNK_OVERLAP = 120

    def __init__(
        self,
        vector_db_dir: Path | None = None,
        embedding_model: str = EMBEDDING_MODEL,
    ) -> None:
        self.vector_db_dir = vector_db_dir or VECTOR_DB_DIR
        self.vector_db_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(self.vector_db_dir))
        self.collection = self._get_or_create_collection()
        self.embedder = SentenceTransformer(embedding_model)

    def _get_or_create_collection(self) -> Collection:
        return self.client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "Freddy cybersecurity local knowledge index"},
        )

    def iter_source_files(self) -> Iterable[tuple[Path, str]]:
        for category, base_dir in (("knowledge", KNOWLEDGE_DIR), ("vulnerability", VULNERABILITY_DIR)):
            if not base_dir.exists():
                continue
            for file_path in sorted(base_dir.glob("*.md")):
                yield file_path, category

    def index_all(self) -> dict[str, int]:
        ids: list[str] = []
        documents: list[str] = []
        embeddings: list[list[float]] = []
        metadatas: list[dict[str, str]] = []
        indexed_files = 0

        for file_path, category in self.iter_source_files():
            text = file_path.read_text(encoding="utf-8")
            chunks = self.chunk_text(text)
            indexed_files += 1
            for index, chunk in enumerate(chunks):
                chunk_id = self._chunk_id(file_path, index)
                ids.append(chunk_id)
                documents.append(chunk)
                embeddings.append(self.embedder.encode(chunk).tolist())
                metadatas.append(
                    {
                        "source": str(file_path.relative_to(BASE_DIR)).replace('\\', '/'),
                        "category": category,
                        "title": self._extract_title(text, file_path.stem),
                        "slug": file_path.stem,
                    }
                )

        self._reset_collection()
        if ids:
            self.collection.upsert(
                ids=ids,
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
            )
        return {"files": indexed_files, "chunks": len(ids)}

    def query(self, query: str, top_k: int = 5) -> list[KnowledgeMatch]:
        if not query.strip() or self.collection.count() == 0:
            return []

        query_embedding = self.embedder.encode(query).tolist()
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )

        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        matches: list[KnowledgeMatch] = []
        for document, metadata, distance in zip(documents, metadatas, distances):
            matches.append(
                KnowledgeMatch(
                    document=document,
                    source=metadata.get("source", "unknown"),
                    category=metadata.get("category", "knowledge"),
                    score=max(0.0, 1.0 - float(distance)),
                    title=metadata.get("title", metadata.get("slug", "Knowledge")),
                    slug=metadata.get("slug", "unknown"),
                )
            )
        return matches

    def recommended_query(self, evidence: str, command_name: str, target: str | None, rule_titles: list[str]) -> str:
        terms: list[str] = [command_name]
        if target:
            terms.append(target)
        terms.extend(rule_titles[:4])
        lower_evidence = evidence.lower()
        for keyword in (
            "ssh", "tls", "ssl", "redis", "mysql", "postgres", "postgresql", "elasticsearch",
            "brute force", "401", "403", "404", "admin", "security headers", "open ports", "web",
        ):
            if keyword in lower_evidence:
                terms.append(keyword)
        query = " ".join(dict.fromkeys(term for term in terms if term))
        return query.strip() or command_name

    @classmethod
    def chunk_text(cls, text: str) -> list[str]:
        normalized = re.sub(r"\n{3,}", "\n\n", text.strip())
        if len(normalized) <= cls.CHUNK_SIZE:
            return [normalized]
        chunks: list[str] = []
        start = 0
        while start < len(normalized):
            end = min(start + cls.CHUNK_SIZE, len(normalized))
            boundary = normalized.rfind("\n", start, end)
            if boundary <= start:
                boundary = end
            chunk = normalized[start:boundary].strip()
            if chunk:
                chunks.append(chunk)
            if boundary >= len(normalized):
                break
            start = max(boundary - cls.CHUNK_OVERLAP, 0)
        return chunks

    def _reset_collection(self) -> None:
        try:
            self.client.delete_collection(self.COLLECTION_NAME)
        except Exception:
            pass
        self.collection = self._get_or_create_collection()

    @staticmethod
    def _chunk_id(file_path: Path, index: int) -> str:
        digest = hashlib.sha1(f"{file_path}:{index}".encode("utf-8")).hexdigest()
        return digest

    @staticmethod
    def _extract_title(text: str, fallback: str) -> str:
        first_line = text.splitlines()[0].strip() if text.splitlines() else fallback
        return first_line.lstrip("# ").strip() or fallback.replace("_", " ").title()
