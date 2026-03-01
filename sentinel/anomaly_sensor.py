"""
RAKSHAK - Real-Time Anomaly Detection Sensor
Monitors process creation, CPU spikes, and filesystem activity.
"""

import os
import time
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

import psutil

logger = logging.getLogger("Rakshak.Sensor")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCAN_INTERVAL = 2.0          # seconds between scans
CPU_SPIKE_THRESHOLD = 95.0   # % per process (raised: 85% is normal for compilers, browsers)
CPU_SUSTAINED_COUNT = 2      # must spike N consecutive scans before alerting
RAPID_FILE_CREATE_LIMIT = 20 # files created in one scan window
ALERT_COOLDOWN = 60.0        # seconds before re-alerting on same process+reason type

SUSPICIOUS_NAMES = [
    "fake_malware", "mimikatz", "cobalt_strike",
    "reverse_shell", "keylogger", "cryptominer", "ransomware",
    "meterpreter", "lazagne", "bloodhound", "rubeus",
    "sharphound", "psexec", "procdump",
]

# Well-known safe processes — never flag these for CPU spikes
# (they're still checked for suspicious name matches)
TRUSTED_PROCESSES: Set[str] = {
    # NVIDIA
    "nvcontainer.exe", "nvidia-smi.exe", "nvdisplay.container.exe",
    "nvtelemetrycontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "nvoawrappercache.exe", "nvcplui.exe",
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "msedgewebview2.exe",
    # Dev tools
    "code.exe", "devenv.exe", "rider64.exe", "idea64.exe", "pycharm64.exe",
    "android studio.exe", "node.exe", "git.exe",
    # Communication
    "whatsapp.exe", "telegram.exe", "discord.exe", "slack.exe",
    "teams.exe", "zoom.exe", "skype.exe",
    # Microsoft / Windows
    "explorer.exe", "dwm.exe", "winlogon.exe", "taskhostw.exe",
    "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "ctfmon.exe",
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "sihost.exe", "fontdrvhost.exe", "conhost.exe", "dllhost.exe",
    "applicationframehost.exe", "widgets.exe", "widgetservice.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "smartscreen.exe", "sgrmbroker.exe",
    "gameinputsvc.exe", "gamebarpresencewriter.exe",
    "searchprotocolhost.exe", "searchindexer.exe", "searchfilterhost.exe",
    # AMD
    "amdrsserv.exe", "amddvr.exe", "amdow.exe", "cncmd.exe",
    "radeonsofrware.exe",
    # Misc common apps
    "spotify.exe", "steam.exe", "steamwebhelper.exe",
    "onedrive.exe", "phoneexperiencehost.exe",
    # System utilities
    "powertoys.exe", "powertoys.colorpicker.exe",
    "powertoys.fancyzones.exe", "powertoys.keyboardmanager.exe",
    "powertoys.runner.exe",
    # Flutter / Dart
    "dart.exe", "flutter.bat",
}


@dataclass
class ThreatEvent:
    timestamp: str
    pid: int
    process_name: str
    reason: str
    severity: str          # LOW, MEDIUM, HIGH, CRITICAL
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Filesystem watcher (lightweight polling approach)
# ---------------------------------------------------------------------------
class DirectoryWatcher:
    """Track rapid file creation inside watched directories."""

    def __init__(self, watch_dirs: Optional[List[str]] = None):
        temp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
        self.watch_dirs = watch_dirs or [temp]
        self._baseline: Dict[str, set] = {}
        self._refresh_baseline()

    def _refresh_baseline(self):
        for d in self.watch_dirs:
            try:
                self._baseline[d] = set(os.listdir(d))
            except OSError:
                self._baseline[d] = set()

    def check_new_files(self) -> Dict[str, List[str]]:
        """Return {dir: [new_filenames]} since last baseline."""
        results = {}
        for d in self.watch_dirs:
            try:
                current = set(os.listdir(d))
            except OSError:
                current = set()
            new = current - self._baseline.get(d, set())
            if new:
                results[d] = sorted(new)
            self._baseline[d] = current
        return results


# ---------------------------------------------------------------------------
# Core Sensor
# ---------------------------------------------------------------------------
class AnomalySensor:
    """Monitors the system in a background thread and emits ThreatEvents."""

    def __init__(
        self,
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
        watch_dirs: Optional[List[str]] = None,
        scan_interval: float = SCAN_INTERVAL,
    ):
        self.on_threat = on_threat or self._default_handler
        self.scan_interval = scan_interval
        self.dir_watcher = DirectoryWatcher(watch_dirs)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_pids: set = set()
        self.event_log: List[ThreatEvent] = []
        # Cooldown tracking: (pid, reason_type) -> last_alert_time
        self._alert_cooldowns: Dict[tuple, float] = {}
        # Sustained CPU tracking: pid -> consecutive_spike_count
        self._cpu_spike_counts: Dict[int, int] = {}

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._known_pids = {p.pid for p in psutil.process_iter()}
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Anomaly sensor started (interval=%.1fs)", self.scan_interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Anomaly sensor stopped.")

    # -- main loop -----------------------------------------------------------
    def _loop(self):
        while self._running:
            try:
                self._scan_processes()
                self._scan_filesystem()
                self._cleanup_cooldowns()
            except Exception as exc:
                logger.error("Sensor scan error: %s", exc)
            time.sleep(self.scan_interval)

    # -- process scanning ----------------------------------------------------
    # PIDs to ignore (Windows system pseudo-processes report bogus CPU values)
    _IGNORE_PIDS = {0, 4}  # System Idle Process, System

    def _scan_processes(self):
        current_pids = set()
        seen_cpu_pids = set()

        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "cmdline"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info["name"] or "").lower()
                current_pids.add(pid)

                # Skip Windows system pseudo-processes
                if pid in self._IGNORE_PIDS:
                    continue

                # Skip our own process to avoid self-detection
                if pid == os.getpid():
                    continue

                # --- Check 1: suspicious name ---
                if any(s in name for s in SUSPICIOUS_NAMES):
                    if self._can_alert(pid, "suspicious_name"):
                        self._emit(ThreatEvent(
                            timestamp=self._now(),
                            pid=pid,
                            process_name=info["name"],
                            reason="Suspicious process name matches known threat pattern",
                            severity="HIGH",
                            details={"cmdline": info.get("cmdline", [])},
                        ))

                # --- Check 2: CPU spike (sustained, non-trusted only) ---
                cpu = info.get("cpu_percent") or 0.0
                if cpu > CPU_SPIKE_THRESHOLD and name not in TRUSTED_PROCESSES:
                    seen_cpu_pids.add(pid)
                    count = self._cpu_spike_counts.get(pid, 0) + 1
                    self._cpu_spike_counts[pid] = count
                    if count >= CPU_SUSTAINED_COUNT and self._can_alert(pid, "cpu_spike"):
                        self._emit(ThreatEvent(
                            timestamp=self._now(),
                            pid=pid,
                            process_name=info["name"],
                            reason=f"Sustained high CPU: {cpu:.1f}% for {count} consecutive scans",
                            severity="MEDIUM",
                            details={"cpu_percent": cpu, "sustained_count": count},
                        ))

                # --- Check 3: new process since last scan ---
                if pid not in self._known_pids:
                    logger.debug("New process detected: %s (PID %d)", info["name"], pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Reset spike counter for processes that dropped below threshold
        for pid in list(self._cpu_spike_counts.keys()):
            if pid not in seen_cpu_pids:
                del self._cpu_spike_counts[pid]

        self._known_pids = current_pids

    # -- filesystem scanning -------------------------------------------------
    def _scan_filesystem(self):
        new_files = self.dir_watcher.check_new_files()
        for directory, files in new_files.items():
            if len(files) >= RAPID_FILE_CREATE_LIMIT:
                if self._can_alert(0, f"rapid_files_{directory}"):
                    self._emit(ThreatEvent(
                        timestamp=self._now(),
                        pid=0,
                        process_name="filesystem",
                        reason=f"Rapid file creation spike: {len(files)} new files in {directory}",
                        severity="HIGH",
                        details={
                            "directory": directory,
                            "file_count": len(files),
                            "sample_files": files[:10],
                        },
                    ))

    # -- cooldown management -------------------------------------------------
    def _can_alert(self, pid: int, reason_type: str) -> bool:
        """Check if enough time has passed since the last alert for this pid+reason."""
        key = (pid, reason_type)
        now = time.time()
        last = self._alert_cooldowns.get(key, 0)
        if now - last < ALERT_COOLDOWN:
            return False
        self._alert_cooldowns[key] = now
        return True

    def _cleanup_cooldowns(self):
        """Remove expired cooldown entries to avoid memory leak."""
        now = time.time()
        expired = [k for k, v in self._alert_cooldowns.items() if now - v > ALERT_COOLDOWN * 2]
        for k in expired:
            del self._alert_cooldowns[k]

    # -- helpers -------------------------------------------------------------
    def _emit(self, event: ThreatEvent):
        self.event_log.append(event)
        logger.warning("THREAT [%s] PID=%d %s: %s",
                        event.severity, event.pid, event.process_name, event.reason)
        try:
            self.on_threat(event)
        except Exception as exc:
            logger.error("Threat callback error: %s", exc)

    @staticmethod
    def _default_handler(event: ThreatEvent):
        print(f"[!] THREAT {event.severity} | {event.process_name} (PID {event.pid}): {event.reason}")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
