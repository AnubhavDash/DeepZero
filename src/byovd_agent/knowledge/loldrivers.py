from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LOLDriversDB:
    """indexed database of loldrivers.io entries for fast hash lookups"""

    def __init__(self, db_path: str | Path):
        self._entries: list[dict[str, Any]] = []
        self._sha256_set: set[str] = set()
        self._md5_set: set[str] = set()
        self._imphash_set: set[str] = set()
        self._by_sha256: dict[str, dict] = {}
        self._load(Path(db_path))

    def _load(self, path: Path) -> None:
        raw = path.read_text(encoding="utf-8")
        self._entries = json.loads(raw)

        for entry in self._entries:
            for sample in entry.get("KnownVulnerableSamples", []):
                sha = sample.get("SHA256", "")
                if sha:
                    key = sha.lower()
                    self._sha256_set.add(key)
                    self._by_sha256[key] = entry

                md5 = sample.get("MD5", "")
                if md5:
                    self._md5_set.add(md5.lower())

                imp = sample.get("Imphash", "")
                if imp:
                    self._imphash_set.add(imp.lower())

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    @property
    def total_hashes(self) -> int:
        return len(self._sha256_set)

    def is_known(self, sha256: str) -> bool:
        return sha256.lower() in self._sha256_set

    def lookup(self, sha256: str) -> dict | None:
        return self._by_sha256.get(sha256.lower())

    def format_entry(self, entry: dict) -> str:
        """compact summary of a loldrivers entry for context"""
        lines = [f"ID: {entry.get('Id', '?')}"]
        lines.append(f"Tags: {', '.join(entry.get('Tags', []))}")

        cves = [c for c in entry.get("CVE", []) if c and c.strip()]
        if cves:
            lines.append(f"CVEs: {', '.join(cves)}")

        cmds = entry.get("Commands", {})
        if cmds:
            lines.append(f"Use Case: {cmds.get('Usecase', '')}")
            desc = cmds.get("Description", "")
            if desc:
                lines.append(f"Description: {desc[:300]}")

        return "\n".join(lines)
