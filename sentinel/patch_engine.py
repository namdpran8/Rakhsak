"""
RAKSHAK - Auto-Patch Suggestion Engine
Generates remediation suggestions for detected threats.
All patches require HUMAN APPROVAL before execution (ethics-first design).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger("Rakshak.Patcher")


class PatchStatus(Enum):
    PENDING = "pending"           # Awaiting human approval
    APPROVED = "approved"         # Human approved, ready to execute
    REJECTED = "rejected"         # Human rejected
    APPLIED = "applied"           # Successfully applied
    FAILED = "failed"             # Application failed


@dataclass
class PatchSuggestion:
    """A suggested remediation action that requires human approval."""
    id: str
    timestamp: str
    threat_type: str            # anomaly_type or scan rule name
    severity: str
    target: str                 # PID, file path, registry key, etc.
    action: str                 # kill_process, quarantine_file, block_ip, etc.
    description: str            # Human-readable explanation
    command: str                # The actual command/action to take
    risk_level: str             # LOW, MEDIUM, HIGH
    reversible: bool            # Can this action be undone?
    status: PatchStatus = PatchStatus.PENDING
    approved_by: Optional[str] = None
    applied_at: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "target": self.target,
            "action": self.action,
            "description": self.description,
            "command": self.command,
            "risk_level": self.risk_level,
            "reversible": self.reversible,
            "status": self.status.value,
            "approved_by": self.approved_by,
            "applied_at": self.applied_at,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Patch generation rules
# ---------------------------------------------------------------------------
_PATCH_COUNTER = 0


def _next_id() -> str:
    global _PATCH_COUNTER
    _PATCH_COUNTER += 1
    return f"PATCH-{_PATCH_COUNTER:04d}"


def generate_patches_for_threat(
    threat_type: str,
    severity: str,
    pid: int = 0,
    process_name: str = "",
    file_path: str = "",
    details: dict = None,
) -> List[PatchSuggestion]:
    """Generate remediation suggestions based on threat type."""
    details = details or {}
    patches = []
    now = datetime.now(timezone.utc).isoformat()

    # --- Process-based threats ---
    if pid > 0 and process_name:
        if severity in ("CRITICAL", "HIGH", "MALICIOUS"):
            patches.append(PatchSuggestion(
                id=_next_id(),
                timestamp=now,
                threat_type=threat_type,
                severity=severity,
                target=f"{process_name} (PID {pid})",
                action="kill_process",
                description=f"Terminate the suspicious process '{process_name}' (PID {pid})",
                command=f"taskkill /PID {pid} /F",
                risk_level="MEDIUM",
                reversible=False,
                details={"pid": pid, "process_name": process_name},
            ))

        # Suggest network isolation for C2-like behavior
        if "network" in threat_type or "reverse_shell" in threat_type:
            patches.append(PatchSuggestion(
                id=_next_id(),
                timestamp=now,
                threat_type=threat_type,
                severity=severity,
                target=f"{process_name} (PID {pid})",
                action="block_network",
                description=f"Block all network access for '{process_name}'",
                command=f"netsh advfirewall firewall add rule name=\"EG_Block_{pid}\" "
                        f"dir=out action=block program=\"{process_name}\"",
                risk_level="LOW",
                reversible=True,
                details={"pid": pid, "reverse_cmd":
                         f"netsh advfirewall firewall delete rule name=\"EG_Block_{pid}\""},
            ))

    # --- File-based threats ---
    if file_path:
        if "credential_leak" in threat_type or "private_key" in threat_type:
            patches.append(PatchSuggestion(
                id=_next_id(),
                timestamp=now,
                threat_type=threat_type,
                severity=severity,
                target=file_path,
                action="redact_secrets",
                description=f"Remove hardcoded secrets from '{file_path}' and move to environment variables",
                command=f"# Manual: Replace hardcoded secrets in {file_path} with os.environ['SECRET_NAME']",
                risk_level="LOW",
                reversible=True,
                details={"file_path": file_path},
            ))

        if any(cat in threat_type for cat in ("reverse_shell", "exploit", "obfuscation")):
            patches.append(PatchSuggestion(
                id=_next_id(),
                timestamp=now,
                threat_type=threat_type,
                severity=severity,
                target=file_path,
                action="quarantine_file",
                description=f"Move suspicious file to quarantine: '{file_path}'",
                command=f"move \"{file_path}\" \"%TEMP%\\rakshak_quarantine\\\"",
                risk_level="MEDIUM",
                reversible=True,
                details={"file_path": file_path,
                         "reverse_cmd": f"move \"%TEMP%\\rakshak_quarantine\\{file_path}\" \"{file_path}\""},
            ))

    # --- Filesystem anomalies ---
    if "rapid_file" in threat_type or "ransomware" in threat_type.lower():
        directory = details.get("directory", "")
        patches.append(PatchSuggestion(
            id=_next_id(),
            timestamp=now,
            threat_type=threat_type,
            severity=severity,
            target=directory or "affected directory",
            action="restrict_directory",
            description=f"Set read-only permissions on affected directory to halt file encryption",
            command=f"icacls \"{directory}\" /deny Everyone:(W,D)",
            risk_level="HIGH",
            reversible=True,
            details={"directory": directory,
                     "reverse_cmd": f"icacls \"{directory}\" /remove:d Everyone"},
        ))

    # --- Behavioral anomalies ---
    if "spawn_storm" in threat_type:
        patches.append(PatchSuggestion(
            id=_next_id(),
            timestamp=now,
            threat_type=threat_type,
            severity=severity,
            target=f"{process_name} (PID {pid})",
            action="suspend_process_tree",
            description=f"Suspend the entire process tree rooted at '{process_name}'",
            command=f"# Suspend PID {pid} and all child processes",
            risk_level="MEDIUM",
            reversible=True,
            details={"pid": pid},
        ))

    if "io_write_spike" in threat_type:
        patches.append(PatchSuggestion(
            id=_next_id(),
            timestamp=now,
            threat_type=threat_type,
            severity=severity,
            target=f"{process_name} (PID {pid})",
            action="throttle_io",
            description=f"Throttle disk I/O for '{process_name}' to prevent data destruction",
            command=f"# Set I/O priority to low for PID {pid}",
            risk_level="LOW",
            reversible=True,
            details={"pid": pid},
        ))

    # --- Add Windows Defender scan as a universal suggestion for HIGH+ ---
    if severity in ("CRITICAL", "HIGH", "MALICIOUS"):
        scan_target = file_path or "C:\\"
        patches.append(PatchSuggestion(
            id=_next_id(),
            timestamp=now,
            threat_type=threat_type,
            severity=severity,
            target=scan_target,
            action="defender_scan",
            description="Run a targeted Windows Defender scan on the affected path",
            command=f"Start-MpScan -ScanType CustomScan -ScanPath \"{scan_target}\"",
            risk_level="LOW",
            reversible=False,
        ))

    return patches


# ---------------------------------------------------------------------------
# Patch Manager (tracks approval state)
# ---------------------------------------------------------------------------
class PatchManager:
    """Manages patch suggestions with human-in-the-loop approval flow."""

    def __init__(self):
        self._patches: Dict[str, PatchSuggestion] = {}
        self.total_suggested = 0
        self.total_approved = 0
        self.total_rejected = 0
        self.total_applied = 0

    def add_suggestion(self, patch: PatchSuggestion):
        self._patches[patch.id] = patch
        self.total_suggested += 1
        logger.info("Patch suggested: %s - %s (%s)",
                     patch.id, patch.action, patch.target)

    def add_suggestions(self, patches: List[PatchSuggestion]):
        for p in patches:
            self.add_suggestion(p)

    def approve(self, patch_id: str, approved_by: str = "operator") -> bool:
        patch = self._patches.get(patch_id)
        if patch and patch.status == PatchStatus.PENDING:
            patch.status = PatchStatus.APPROVED
            patch.approved_by = approved_by
            self.total_approved += 1
            logger.info("Patch APPROVED: %s by %s", patch_id, approved_by)
            return True
        return False

    def reject(self, patch_id: str) -> bool:
        patch = self._patches.get(patch_id)
        if patch and patch.status == PatchStatus.PENDING:
            patch.status = PatchStatus.REJECTED
            self.total_rejected += 1
            logger.info("Patch REJECTED: %s", patch_id)
            return True
        return False

    def get_pending(self) -> List[PatchSuggestion]:
        return [p for p in self._patches.values() if p.status == PatchStatus.PENDING]

    def get_all(self) -> List[PatchSuggestion]:
        return list(self._patches.values())

    def get_by_id(self, patch_id: str) -> Optional[PatchSuggestion]:
        return self._patches.get(patch_id)

    def get_metrics(self) -> dict:
        return {
            "total_suggested": self.total_suggested,
            "total_approved": self.total_approved,
            "total_rejected": self.total_rejected,
            "total_applied": self.total_applied,
            "pending_count": len(self.get_pending()),
        }
