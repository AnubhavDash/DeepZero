from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Config:
    model: str = "google_vertexai:gemini-2.5-pro"
    ghidra_install_dir: Path = Path(".")
    loldrivers_db: Path = Path("loldrivers.io.json")
    work_dir: Path = Path("work")
    samples_dir: Path = Path("samples")
    reports_dir: Path = Path("reports")
    project_root: Path = field(default_factory=lambda: Path.cwd())

    @classmethod
    def from_env(cls, dotenv_path: str | None = None) -> Config:
        load_dotenv(dotenv_path)

        project_root = Path(os.getenv("PROJECT_ROOT", Path.cwd()))

        def resolve(val: str, default: str) -> Path:
            p = Path(os.getenv(val, default))
            if not p.is_absolute():
                p = project_root / p
            return p

        return cls(
            model=os.getenv("BYOVD_MODEL", "google_vertexai:gemini-2.5-pro"),
            ghidra_install_dir=Path(os.getenv("GHIDRA_INSTALL_DIR", ".")),
            loldrivers_db=resolve("LOLDRIVERS_DB", "loldrivers.io.json"),
            work_dir=resolve("WORK_DIR", "work"),
            samples_dir=resolve("SAMPLES_DIR", "samples"),
            reports_dir=resolve("REPORTS_DIR", "reports"),
            project_root=project_root,
        )

    def ensure_dirs(self) -> None:
        for d in (self.work_dir, self.samples_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
