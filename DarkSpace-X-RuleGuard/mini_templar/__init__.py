"""Offline Mini Templar: safeguards_adapter scoring + entropy rescue (no LLM, no DB)."""

__version__ = "0.4.6-mini-templar"
__codename__ = "Parva Sed Fortis"

from mini_templar.core import ClassificationResult, classify_mini_templar

__all__ = [
    "ClassificationResult",
    "classify_mini_templar",
    "__version__",
    "__codename__",
]