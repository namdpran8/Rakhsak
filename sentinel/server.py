"""
RAKSHAK v2 - WebSocket API Server
Integrates: anomaly sensor, behavioral detector, code scanner, patch engine.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Set

import psutil
import websockets

from sentinel.hardware_detect import select_providers
from sentinel.anomaly_sensor import AnomalySensor, ThreatEvent
from sentinel.behavioral_detector import BehavioralDetector, BehaviorAnomaly
from sentinel.code_scanner import CodeScanner, ScanFinding
from sentinel.ai_brain import AIBrain, analyze_behavioral, analyze_scan_finding
from sentinel.patch_engine import PatchManager, generate_patches_for_threat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Rakshak.API")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
connected_clients: Set = set()
event_queue: asyncio.Queue = None
sensor: AnomalySensor = None
behavioral: BehavioralDetector = None
scanner: CodeScanner = None
brain: AIBrain = None
patch_mgr: PatchManager = None
hw_meta: dict = {}
_loop: asyncio.AbstractEventLoop = None
_start_time: float = 0

HOST = "127.0.0.1"
PORT = 8765


# ---------------------------------------------------------------------------
# System metrics
# ---------------------------------------------------------------------------
def system_snapshot() -> dict:
    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
    net = psutil.net_io_counters()

    beh_metrics = behavioral.get_metrics() if behavioral else {}
    scan_metrics = scanner.get_metrics() if scanner else {}
    patch_metrics = patch_mgr.get_metrics() if patch_mgr else {}

    return {
        "type": "metrics",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used_gb": round(mem.used / (1024**3), 2),
        "memory_total_gb": round(mem.total / (1024**3), 2),
        "disk_percent": disk.percent,
        "net_sent_mb": round(net.bytes_sent / (1024**2), 1),
        "net_recv_mb": round(net.bytes_recv / (1024**2), 1),
        "process_count": len(psutil.pids()),
        "hardware": hw_meta,
        "uptime_seconds": round(time.time() - _start_time),
        "behavioral": beh_metrics,
        "scanner": scan_metrics,
        "patches": patch_metrics,
    }


# ---------------------------------------------------------------------------
# Callbacks (called from background threads)
# ---------------------------------------------------------------------------
def _enqueue(payload: dict):
    if _loop is not None and _loop.is_running():
        _loop.call_soon_threadsafe(event_queue.put_nowait, payload)


def on_threat_detected(event: ThreatEvent):
    analysis = brain.analyze(event.process_name, event.reason, event.details)
    patches = generate_patches_for_threat(
        threat_type=event.reason,
        severity=analysis.get("verdict", event.severity),
        pid=event.pid,
        process_name=event.process_name,
        details=event.details,
    )
    patch_mgr.add_suggestions(patches)
    _enqueue({
        "type": "threat",
        "event": event.to_dict(),
        "analysis": analysis,
        "patches": [p.to_dict() for p in patches],
    })


def on_behavioral_anomaly(anomaly: BehaviorAnomaly):
    analysis = analyze_behavioral(
        anomaly_type=anomaly.anomaly_type,
        process_name=anomaly.process_name,
        baseline=anomaly.baseline_value,
        observed=anomaly.observed_value,
        zscore=anomaly.zscore,
        parent_chain=anomaly.parent_chain,
    )
    patches = generate_patches_for_threat(
        threat_type=anomaly.anomaly_type,
        severity=analysis.get("verdict", anomaly.severity),
        pid=anomaly.pid,
        process_name=anomaly.process_name,
        details=anomaly.details,
    )
    patch_mgr.add_suggestions(patches)
    _enqueue({
        "type": "behavioral",
        "event": anomaly.to_dict(),
        "analysis": analysis,
        "patches": [p.to_dict() for p in patches],
    })


def on_scan_finding(finding: ScanFinding):
    analysis = analyze_scan_finding(
        rule_name=finding.rule_name,
        severity=finding.severity,
        category=finding.category,
        description=finding.description,
        file_path=finding.file_path,
        line_number=finding.line_number,
        matched_text=finding.matched_text,
    )
    patches = generate_patches_for_threat(
        threat_type=finding.category,
        severity=finding.severity,
        file_path=finding.file_path,
        details={"rule": finding.rule_name, "line": finding.line_number},
    )
    patch_mgr.add_suggestions(patches)
    _enqueue({
        "type": "scan_finding",
        "event": finding.to_dict(),
        "analysis": analysis,
        "patches": [p.to_dict() for p in patches],
    })


# ---------------------------------------------------------------------------
# WebSocket handlers
# ---------------------------------------------------------------------------
async def handler(websocket):
    connected_clients.add(websocket)
    logger.info("Client connected (total: %d)", len(connected_clients))

    init = {
        "type": "init",
        "hardware": hw_meta,
        "engine": "phi3.5-mini-onnx" if brain.model_loaded else "rule-based",
        "server_version": "2.0.0-mvp",
        "features": ["behavioral", "code_scanner", "patch_engine", "ethics_layer"],
    }
    await websocket.send(json.dumps(init))

    try:
        async for message in websocket:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send(json.dumps({"type": "pong"}))
            elif msg_type == "request_snapshot":
                await websocket.send(json.dumps(system_snapshot()))
            elif msg_type == "approve_patch":
                patch_id = data.get("patch_id", "")
                ok = patch_mgr.approve(patch_id, approved_by="dashboard_operator")
                await websocket.send(json.dumps({
                    "type": "patch_response", "patch_id": patch_id, "approved": ok,
                }))
            elif msg_type == "reject_patch":
                patch_id = data.get("patch_id", "")
                ok = patch_mgr.reject(patch_id)
                await websocket.send(json.dumps({
                    "type": "patch_response", "patch_id": patch_id, "rejected": ok,
                }))
            elif msg_type == "get_patches":
                pending = patch_mgr.get_pending()
                await websocket.send(json.dumps({
                    "type": "patches_list",
                    "patches": [p.to_dict() for p in pending],
                }))
            elif msg_type == "scan_file":
                fpath = data.get("path", "")
                if fpath and os.path.isfile(fpath):
                    findings = scanner.scan_file(fpath)
                    await websocket.send(json.dumps({
                        "type": "scan_result", "path": fpath,
                        "findings": [f.to_dict() for f in findings],
                    }))
    except websockets.ConnectionClosed:
        pass
    finally:
        connected_clients.discard(websocket)
        logger.info("Client disconnected (total: %d)", len(connected_clients))


async def broadcast(message: dict):
    if connected_clients:
        payload = json.dumps(message, default=str)
        websockets.broadcast(connected_clients, payload)


async def metrics_broadcaster():
    while True:
        await broadcast(system_snapshot())
        await asyncio.sleep(2)


async def event_broadcaster():
    while True:
        payload = await event_queue.get()
        await broadcast(payload)
        logger.info("Broadcast event to %d clients", len(connected_clients))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    global event_queue, sensor, behavioral, scanner, brain, patch_mgr
    global hw_meta, _loop, _start_time

    _loop = asyncio.get_running_loop()
    _start_time = time.time()

    print("=" * 60)
    print("   RAKSHAK v2.0 - AI Cybersecurity Sentinel")
    print("   Local-First | Behavioral AI | Zero-Day Detection")
    print("=" * 60)

    # Hardware detection
    providers, hw_meta = select_providers()
    print(f"[*] Device    : {hw_meta['selected_device']}")
    print(f"[*] Providers : {providers}")

    # AI Brain
    brain = AIBrain(providers=providers)
    engine = "Phi-3.5-mini ONNX" if brain.model_loaded else "Rule-Based + Behavioral Z-Score"
    print(f"[*] AI Engine : {engine}")

    # Patch manager
    patch_mgr = PatchManager()

    # Event queue
    event_queue = asyncio.Queue()

    # Anomaly sensor (signature + name-based)
    sensor = AnomalySensor(on_threat=on_threat_detected)
    sensor.start()
    print(f"[*] Sensor    : ACTIVE (interval={sensor.scan_interval}s)")

    # Behavioral detector (z-score based, no signatures)
    behavioral = BehavioralDetector(on_anomaly=on_behavioral_anomaly, scan_interval=3.0)
    behavioral.start()
    print("[*] Behavioral: ACTIVE (z-score threshold=3.5, warmup=3 scans)")

    # Code scanner
    watch_dirs = []
    temp_dir = os.environ.get("TEMP", os.environ.get("TMP", ""))
    if temp_dir:
        watch_dirs.append(temp_dir)
    scanner = CodeScanner(on_finding=on_scan_finding, watch_dirs=watch_dirs, scan_interval=10.0)
    scanner.start()
    print(f"[*] Scanner   : ACTIVE (watching {len(watch_dirs)} dirs)")

    print("[*] Patches   : ACTIVE (human approval required)")
    print(f"[*] API       : ws://{HOST}:{PORT}")
    print("=" * 60)
    print("[*] Rakshak is online. All defense layers active.")
    print()

    async with websockets.serve(handler, HOST, PORT):
        await asyncio.gather(
            metrics_broadcaster(),
            event_broadcaster(),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Rakshak shutting down.")
        if sensor:
            sensor.stop()
        if behavioral:
            behavioral.stop()
        if scanner:
            scanner.stop()
