"""
legionforge_guardian
────────────────────
Deterministic security sidecar for LLM agent frameworks.

Phase G2 note: this package currently re-exports from LegionForge's
src.security.guardian module (editable install). In Phase G3 the
canonical code moves here and src.security.guardian becomes the shim.

Public API:
    GuardianClient     — async HTTP client for /check and /report
    guardian_check()   — convenience coroutine (single call)
    GuardianCheckResponse — response model
"""

from legionforge_guardian.sdk.client import GuardianClient, guardian_check

__all__ = [
    "GuardianClient",
    "guardian_check",
]

__version__ = "0.1.0"
