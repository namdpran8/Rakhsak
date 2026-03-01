"""
RAKSHAK - Behavioral Anomaly Detection Engine
Uses statistical baselines and process behavior graphs instead of signatures.
Detects zero-day-like anomalies by flagging deviations from learned norms.
"""

import os
import time
import logging
import threading
import collections
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger("Rakshak.Behavioral")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASELINE_WINDOW = 60         # seconds of history to keep per process
ZSCORE_THRESHOLD = 3.5       # standard deviations before flagging (raised from 3.0)
MIN_BASELINE_SAMPLES = 10   # need this many samples before flagging (raised from 5)
PARENT_CHAIN_DEPTH = 5       # how far up the process tree to walk
SPAWN_STORM_THRESHOLD = 8   # new children in one scan window (raised from 5)
ALERT_COOLDOWN = 120.0       # seconds before re-alerting same process+anomaly type

# Minimum absolute values before a z-score spike matters.
# This prevents flagging CPU going from 0.1% to 2% (huge z-score, harmless).
MIN_ABSOLUTE_THRESHOLDS = {
    "cpu":      15.0,   # CPU % must be above this to trigger
    "memory":   10.0,   # Memory % must be above this
    "io_write": 50.0,   # MB written must be above this
    "io_read":  50.0,   # MB read must be above this
    "network":  10,     # connections must be above this
    "threads":  50,     # thread count must be above this
}


@dataclass
class ProcessProfile:
    """Rolling statistical profile of a single process."""
    pid: int
    name: str
    first_seen: float = field(default_factory=time.time)
    cpu_samples: list = field(default_factory=list)
    mem_samples: list = field(default_factory=list)
    io_read_samples: list = field(default_factory=list)
    io_write_samples: list = field(default_factory=list)
    thread_counts: list = field(default_factory=list)
    connection_counts: list = field(default_factory=list)
    children_spawned: int = 0
    last_children: set = field(default_factory=set)
    flagged: bool = False


@dataclass
class BehaviorAnomaly:
    """A detected behavioral anomaly."""
    timestamp: str
    pid: int
    process_name: str
    anomaly_type: str
    severity: str
    description: str
    baseline_value: float
    observed_value: float
    zscore: float
    parent_chain: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_name": self.process_name,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "baseline_value": round(self.baseline_value, 2),
            "observed_value": round(self.observed_value, 2),
            "zscore": round(self.zscore, 2),
            "parent_chain": self.parent_chain,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------
def _mean(values: list) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: list) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / len(values)
    return variance ** 0.5


def _zscore(value: float, values: list) -> float:
    """How many standard deviations is value from the mean of values."""
    sd = _stddev(values)
    if sd == 0:
        return 0.0
    return (value - _mean(values)) / sd


# ---------------------------------------------------------------------------
# Process tree helpers
# ---------------------------------------------------------------------------
def _get_parent_chain(pid: int, depth: int = PARENT_CHAIN_DEPTH) -> List[str]:
    """Walk up the process tree and return [child -> parent -> grandparent ...]."""
    chain = []
    current = pid
    for _ in range(depth):
        try:
            proc = psutil.Process(current)
            parent = proc.parent()
            if parent is None:
                break
            chain.append(f"{parent.name()}({parent.pid})")
            current = parent.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    return chain


# Processes to completely skip — system-level and well-known safe apps
SYSTEM_PIDS = {0, 4}
SKIP_PROCESSES = {
    # Windows core
    "system idle process", "system", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "winlogon.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
    "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "ctfmon.exe",
    "conhost.exe", "dllhost.exe", "applicationframehost.exe",
    "widgetservice.exe", "widgets.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "msedge.exe", "msedgewebview2.exe",
    "smartscreen.exe", "sgrmbroker.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe",
    "gameinputsvc.exe", "gamebarpresencewriter.exe",
    # NVIDIA
    "nvcontainer.exe", "nvidia-smi.exe", "nvdisplay.container.exe",
    "nvtelemetrycontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "nvoawrappercache.exe", "nvcplui.exe",
    # AMD
    "amdrsserv.exe", "amddvr.exe", "amdow.exe", "cncmd.exe",
    "radeonsofrware.exe",
    # Browsers
    "chrome.exe", "firefox.exe", "opera.exe", "brave.exe",
    # Communication
    "whatsapp.exe", "telegram.exe", "discord.exe", "slack.exe",
    "teams.exe", "zoom.exe", "skype.exe",
    # Dev tools
    "code.exe", "devenv.exe", "rider64.exe", "idea64.exe", "pycharm64.exe",
    "android studio.exe", "node.exe", "git.exe",
    # Common apps
    "spotify.exe", "steam.exe", "steamwebhelper.exe",
    "onedrive.exe", "phoneexperiencehost.exe",
    "powertoys.exe", "powertoys.runner.exe",
    "powertoys.fancyzones.exe", "powertoys.keyboardmanager.exe",
    # Flutter / Dart
    "dart.exe",
}


# ---------------------------------------------------------------------------
# Behavioral Anomaly Detector
# ---------------------------------------------------------------------------
class BehavioralDetector:
    """
    Tracks per-process statistical profiles and flags deviations.
    This is a zero-day detection approach: no signatures required.
    """

    def __init__(
        self,
        on_anomaly: Optional[Callable[[BehaviorAnomaly], None]] = None,
        scan_interval: float = 3.0,
    ):
        self.on_anomaly = on_anomaly or self._default_handler
        self.scan_interval = scan_interval
        self._profiles: Dict[int, ProcessProfile] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.anomaly_log: List[BehaviorAnomaly] = []
        # Cooldown tracking: (pid, anomaly_type) -> last_alert_time
        self._alert_cooldowns: Dict[tuple, float] = {}
        # Metrics
        self.total_scans = 0
        self.total_anomalies = 0
        self.false_positive_overrides = 0

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Behavioral detector started (interval=%.1fs)", self.scan_interval)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Behavioral detector stopped.")

    # -- main loop -----------------------------------------------------------
    def _loop(self):
        # Warm-up: collect baseline samples silently (no alerting)
        for _ in range(3):
            self._scan_all(alerting=False)
            time.sleep(self.scan_interval)

        while self._running:
            try:
                self._scan_all(alerting=True)
                self.total_scans += 1
            except Exception as exc:
                logger.error("Behavioral scan error: %s", exc)
            time.sleep(self.scan_interval)

    def _scan_all(self, alerting: bool = True):
        seen_pids = set()

        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent",
                                          "num_threads", "ppid"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info["name"] or "unknown").lower()
                seen_pids.add(pid)

                # Skip system processes, trusted apps, and our own process
                if pid in SYSTEM_PIDS or name in SKIP_PROCESSES:
                    continue
                if pid == os.getpid():
                    continue

                # Get or create profile
                profile = self._profiles.get(pid)
                if profile is None:
                    initial_children = set()
                    try:
                        initial_children = {c.pid for c in proc.children()}
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    profile = ProcessProfile(
                        pid=pid, name=info["name"] or "unknown",
                        last_children=initial_children,
                    )
                    self._profiles[pid] = profile

                # --- Collect metrics ---
                cpu = info.get("cpu_percent") or 0.0
                mem = info.get("memory_percent") or 0.0
                threads = info.get("num_threads") or 0

                io_read = 0.0
                io_write = 0.0
                try:
                    io = proc.io_counters()
                    io_read = io.read_bytes / (1024 * 1024)
                    io_write = io.write_bytes / (1024 * 1024)
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

                conn_count = 0
                try:
                    conn_count = len(proc.net_connections())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Children
                try:
                    children = {c.pid for c in proc.children()}
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    children = set()
                new_children = children - profile.last_children
                profile.children_spawned += len(new_children)
                profile.last_children = children

                # --- Append to rolling window ---
                max_samples = int(BASELINE_WINDOW / self.scan_interval)
                self._append_capped(profile.cpu_samples, cpu, max_samples)
                self._append_capped(profile.mem_samples, mem, max_samples)
                self._append_capped(profile.io_read_samples, io_read, max_samples)
                self._append_capped(profile.io_write_samples, io_write, max_samples)
                self._append_capped(profile.thread_counts, threads, max_samples)
                self._append_capped(profile.connection_counts, conn_count, max_samples)

                if not alerting:
                    continue

                # --- Check for anomalies (need at least MIN_BASELINE_SAMPLES) ---
                if len(profile.cpu_samples) >= MIN_BASELINE_SAMPLES:
                    self._check_anomaly(profile, "cpu", cpu, profile.cpu_samples,
                                        "CPU usage spike detected")
                    self._check_anomaly(profile, "memory", mem, profile.mem_samples,
                                        "Memory consumption anomaly")
                    self._check_anomaly(profile, "io_write", io_write, profile.io_write_samples,
                                        "Disk write burst detected (possible ransomware/exfil)")
                    self._check_anomaly(profile, "io_read", io_read, profile.io_read_samples,
                                        "Disk read burst detected (possible data harvesting)")
                    self._check_anomaly(profile, "network", conn_count, profile.connection_counts,
                                        "Network connection spike (possible C2 or exfiltration)")
                    self._check_anomaly(profile, "threads", threads, profile.thread_counts,
                                        "Thread count spike (possible fork bomb or injection)")

                # --- Child spawn storm ---
                if len(new_children) > SPAWN_STORM_THRESHOLD:
                    if self._can_alert(pid, "spawn_storm"):
                        self._emit_anomaly(BehaviorAnomaly(
                            timestamp=self._now(),
                            pid=pid,
                            process_name=profile.name,
                            anomaly_type="spawn_storm",
                            severity="HIGH",
                            description=f"Process spawned {len(new_children)} children in one scan window",
                            baseline_value=0,
                            observed_value=len(new_children),
                            zscore=0,
                            parent_chain=_get_parent_chain(pid),
                            details={"new_child_pids": list(new_children)[:10]},
                        ))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Cleanup stale profiles
        stale = set(self._profiles.keys()) - seen_pids
        for pid in stale:
            del self._profiles[pid]

        # Cleanup expired cooldowns
        self._cleanup_cooldowns()

    def _check_anomaly(self, profile: ProcessProfile, metric_name: str,
                       current_value: float, samples: list, description: str):
        """Check if current_value is a statistical anomaly relative to the baseline."""
        # Use all samples except the last one as the baseline
        baseline = samples[:-1]
        z = _zscore(current_value, baseline)
        mean_val = _mean(baseline)

        # Must exceed z-score threshold
        if abs(z) < ZSCORE_THRESHOLD:
            return

        # Must exceed minimum absolute threshold to avoid noise
        min_threshold = MIN_ABSOLUTE_THRESHOLDS.get(metric_name, 1.0)
        if current_value < min_threshold:
            return

        # Must not be in cooldown
        if not self._can_alert(profile.pid, f"{metric_name}_spike"):
            return

        severity = "HIGH" if abs(z) >= 5.0 else "MEDIUM"
        self._emit_anomaly(BehaviorAnomaly(
            timestamp=self._now(),
            pid=profile.pid,
            process_name=profile.name,
            anomaly_type=f"{metric_name}_spike",
            severity=severity,
            description=description,
            baseline_value=mean_val,
            observed_value=current_value,
            zscore=z,
            parent_chain=_get_parent_chain(profile.pid),
        ))

    def _can_alert(self, pid: int, anomaly_type: str) -> bool:
        """Check cooldown: don't re-alert on same process+anomaly within ALERT_COOLDOWN."""
        key = (pid, anomaly_type)
        now = time.time()
        last = self._alert_cooldowns.get(key, 0)
        if now - last < ALERT_COOLDOWN:
            return False
        self._alert_cooldowns[key] = now
        return True

    def _cleanup_cooldowns(self):
        now = time.time()
        expired = [k for k, v in self._alert_cooldowns.items() if now - v > ALERT_COOLDOWN * 2]
        for k in expired:
            del self._alert_cooldowns[k]

    def _emit_anomaly(self, anomaly: BehaviorAnomaly):
        self.anomaly_log.append(anomaly)
        self.total_anomalies += 1
        if len(self.anomaly_log) > 200:
            self.anomaly_log = self.anomaly_log[-200:]
        logger.warning("BEHAVIORAL [%s] PID=%d %s: %s (z=%.1f)",
                        anomaly.severity, anomaly.pid, anomaly.process_name,
                        anomaly.anomaly_type, anomaly.zscore)
        try:
            self.on_anomaly(anomaly)
        except Exception as exc:
            logger.error("Anomaly callback error: %s", exc)

    def get_metrics(self) -> dict:
        """Return benchmarking metrics."""
        return {
            "total_scans": self.total_scans,
            "total_anomalies": self.total_anomalies,
            "tracked_processes": len(self._profiles),
            "false_positive_overrides": self.false_positive_overrides,
            "detection_rate": (self.total_anomalies / max(self.total_scans, 1)) * 100,
        }

    @staticmethod
    def _append_capped(lst: list, value, max_len: int):
        lst.append(value)
        if len(lst) > max_len:
            del lst[0]

    @staticmethod
    def _default_handler(anomaly: BehaviorAnomaly):
        print(f"[BEHAVIORAL] {anomaly.severity} | {anomaly.process_name} "
              f"(PID {anomaly.pid}): {anomaly.anomaly_type} z={anomaly.zscore:.1f}")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
