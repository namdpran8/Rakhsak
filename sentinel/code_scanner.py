"""
RAKSHAK - Real-Time Code & Log Scanner
Scans files for malicious patterns: obfuscated code, hardcoded secrets,
reverse shells, suspicious PowerShell, and common exploit payloads.
"""

import os
import re
import time
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("Rakshak.Scanner")

# ---------------------------------------------------------------------------
# Threat signatures (pattern-based, but behaviorally contextualized)
# ---------------------------------------------------------------------------
@dataclass
class ScanRule:
    name: str
    pattern: str           # regex pattern
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    category: str          # reverse_shell, credential_leak, obfuscation, exploit, suspicious


SCAN_RULES: List[ScanRule] = [
    # Reverse shells
    ScanRule("reverse_shell_python", r"socket\.connect\s*\(\s*\(.*,\s*\d{2,5}\s*\)\s*\)",
             "CRITICAL", "Python reverse shell pattern: socket.connect to remote host", "reverse_shell"),
    ScanRule("reverse_shell_bash", r"(?:bash|sh)\s+-i\s+[>|&].*\/dev\/tcp",
             "CRITICAL", "Bash reverse shell using /dev/tcp", "reverse_shell"),
    ScanRule("reverse_shell_nc", r"(?:nc|ncat|netcat)\s+.*-e\s+(?:\/bin\/(?:ba)?sh|cmd)",
             "CRITICAL", "Netcat reverse shell with command execution", "reverse_shell"),
    ScanRule("reverse_shell_powershell",
             r"New-Object\s+System\.Net\.Sockets\.TCPClient",
             "CRITICAL", "PowerShell TCP client (reverse shell pattern)", "reverse_shell"),

    # Credential and secret leaks
    ScanRule("hardcoded_password", r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
             "HIGH", "Hardcoded password detected in source code", "credential_leak"),
    ScanRule("api_key_leak", r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}['\"]",
             "HIGH", "API key or secret key hardcoded in source", "credential_leak"),
    ScanRule("aws_key", r"AKIA[0-9A-Z]{16}",
             "CRITICAL", "AWS Access Key ID found in source code", "credential_leak"),
    ScanRule("private_key", r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----",
             "CRITICAL", "Private key embedded in source file", "credential_leak"),

    # Obfuscation
    ScanRule("base64_exec", r"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|atob|Base64\.decode)",
             "HIGH", "Execution of base64-decoded payload (code obfuscation)", "obfuscation"),
    ScanRule("eval_dynamic", r"eval\s*\(\s*(?:compile|__import__|chr\(|'\\x)",
             "HIGH", "Dynamic code evaluation with obfuscation", "obfuscation"),
    ScanRule("powershell_encoded", r"-(?:Enc(?:odedCommand)?|e|ec)\s+[A-Za-z0-9+/=]{20,}",
             "HIGH", "PowerShell encoded command execution", "obfuscation"),
    ScanRule("hex_shellcode", r"(?:\\x[0-9a-fA-F]{2}){10,}",
             "HIGH", "Hex-encoded shellcode pattern detected", "obfuscation"),

    # Exploit patterns
    ScanRule("sql_injection", r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|;\s*DELETE\s+FROM)",
             "MEDIUM", "SQL injection payload pattern detected", "exploit"),
    ScanRule("xss_payload", r"<script[^>]*>.*?(?:document\.cookie|alert\s*\(|onerror)",
             "MEDIUM", "Cross-site scripting (XSS) payload detected", "exploit"),
    ScanRule("path_traversal", r"\.\./\.\./\.\./",
             "MEDIUM", "Path traversal attack pattern (../../../)", "exploit"),
    ScanRule("command_injection", r";\s*(?:rm\s+-rf|del\s+/[fqs]|format\s+c:)",
             "CRITICAL", "Command injection with destructive payload", "exploit"),

    # Suspicious OS operations
    ScanRule("disable_defender", r"Set-MpPreference\s+-DisableRealtimeMonitoring",
             "CRITICAL", "Attempt to disable Windows Defender", "suspicious"),
    ScanRule("disable_firewall", r"netsh\s+advfirewall\s+set\s+.*state\s+off",
             "CRITICAL", "Attempt to disable Windows Firewall", "suspicious"),
    ScanRule("registry_run_key", r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             "HIGH", "Registry persistence via Run key", "suspicious"),
    ScanRule("scheduled_task_create", r"schtasks\s+/create\s+.*(?:/sc\s+|/tn\s+)",
             "MEDIUM", "Scheduled task creation (persistence mechanism)", "suspicious"),
    ScanRule("shadow_copy_delete", r"vssadmin\s+delete\s+shadows",
             "CRITICAL", "Shadow copy deletion (ransomware indicator)", "suspicious"),
]

# Compiled patterns for performance
_COMPILED_RULES = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in SCAN_RULES]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".ps1", ".bat", ".cmd", ".sh", ".bash",
    ".rb", ".php", ".java", ".cs", ".go", ".rs", ".c", ".cpp",
    ".h", ".hpp", ".yaml", ".yml", ".json", ".xml", ".toml",
    ".env", ".cfg", ".conf", ".ini", ".log", ".txt", ".sql",
}


@dataclass
class ScanFinding:
    timestamp: str
    file_path: str
    line_number: int
    rule_name: str
    severity: str
    category: str
    description: str
    matched_text: str       # the actual matched text (truncated)
    context_line: str       # the full line (truncated)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "matched_text": self.matched_text[:100],
            "context_line": self.context_line[:200],
        }


# ---------------------------------------------------------------------------
# Code Scanner
# ---------------------------------------------------------------------------
class CodeScanner:
    """Scans files and directories for malicious code patterns."""

    def __init__(
        self,
        on_finding: Optional[Callable[[ScanFinding], None]] = None,
        watch_dirs: Optional[List[str]] = None,
        scan_interval: float = 10.0,
    ):
        self.on_finding = on_finding or self._default_handler
        self.scan_interval = scan_interval
        self.watch_dirs = watch_dirs or []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scanned_files: Dict[str, float] = {}  # path -> last modified time
        self.finding_log: List[ScanFinding] = []
        self.total_files_scanned = 0
        self.total_findings = 0

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Code scanner started (dirs=%s, interval=%.1fs)",
                     self.watch_dirs, self.scan_interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    # -- main loop -----------------------------------------------------------
    def _loop(self):
        while self._running:
            try:
                for watch_dir in self.watch_dirs:
                    if os.path.isdir(watch_dir):
                        self._scan_directory(watch_dir)
            except Exception as exc:
                logger.error("Code scanner error: %s", exc)
            time.sleep(self.scan_interval)

    def _scan_directory(self, directory: str, max_depth: int = 3):
        """Walk directory up to max_depth and scan new/modified files."""
        for root, dirs, files in os.walk(directory):
            depth = root.replace(directory, "").count(os.sep)
            if depth >= max_depth:
                dirs.clear()
                continue
            # Skip hidden dirs and common non-code dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       {"node_modules", "__pycache__", ".git", "venv", ".venv", "build", "dist"}]

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SCANNABLE_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    mtime = os.path.getmtime(fpath)
                except OSError:
                    continue
                # Skip if already scanned and not modified
                if fpath in self._scanned_files and self._scanned_files[fpath] >= mtime:
                    continue
                self._scan_file(fpath)
                self._scanned_files[fpath] = mtime

    def scan_file(self, file_path: str) -> List[ScanFinding]:
        """Public API: scan a single file and return findings."""
        return self._scan_file(file_path)

    def scan_text(self, text: str, source: str = "<inline>") -> List[ScanFinding]:
        """Public API: scan raw text content."""
        return self._scan_content(text, source)

    def _scan_file(self, file_path: str) -> List[ScanFinding]:
        """Scan a single file for malicious patterns."""
        try:
            # Skip large files (>1MB)
            size = os.path.getsize(file_path)
            if size > 1_000_000:
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            self.total_files_scanned += 1
            return self._scan_content(content, file_path)
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", file_path, exc)
            return []

    def _scan_content(self, content: str, source: str) -> List[ScanFinding]:
        """Scan text content against all rules."""
        findings = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Skip comment-only lines and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for rule, compiled in _COMPILED_RULES:
                match = compiled.search(line)
                if match:
                    finding = ScanFinding(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        file_path=source,
                        line_number=line_num,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        matched_text=match.group(0),
                        context_line=stripped,
                    )
                    findings.append(finding)
                    self.finding_log.append(finding)
                    self.total_findings += 1
                    if len(self.finding_log) > 500:
                        self.finding_log = self.finding_log[-500:]
                    logger.warning("SCAN [%s] %s:%d - %s",
                                    rule.severity, source, line_num, rule.name)
                    try:
                        self.on_finding(finding)
                    except Exception as exc:
                        logger.error("Finding callback error: %s", exc)

        return findings

    def get_metrics(self) -> dict:
        return {
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "watched_directories": len(self.watch_dirs),
        }

    @staticmethod
    def _default_handler(finding: ScanFinding):
        print(f"[SCAN] {finding.severity} | {finding.file_path}:{finding.line_number} "
              f"- {finding.rule_name}")
