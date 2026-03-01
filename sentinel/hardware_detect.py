"""
RAKSHAK - Hardware Detection & ONNX Runtime Provider Selection
Detects AMD NPU (Ryzen AI), GPU (DirectML), or falls back to CPU.
"""

import logging
import subprocess
import platform
from typing import List, Tuple

import onnxruntime as ort

logger = logging.getLogger("Rakshak.Hardware")

# Priority order: AMD NPU -> DirectML GPU -> CPU
PROVIDER_PRIORITY = [
    "VitisAIExecutionProvider",
    "DmlExecutionProvider",
    "CPUExecutionProvider",
]


def _detect_amd_npu() -> bool:
    """Check if an AMD Ryzen AI NPU (XDNA/AIE) is available via device enumeration."""
    try:
        if platform.system() != "Windows":
            return False
        result = subprocess.run(
            ["wmic", "path", "Win32_PnPEntity", "where",
             "Caption like '%AMD%IPU%' or Caption like '%AMD%NPU%' or Caption like '%Ryzen%AI%'",
             "get", "Caption"],
            capture_output=True, text=True, timeout=5,
        )
        return "AMD" in result.stdout and ("IPU" in result.stdout or "NPU" in result.stdout)
    except Exception:
        return False


def _detect_gpu_vendor() -> str:
    """Return the name of the primary GPU vendor via PowerShell CIM query."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_VideoController).Name"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.upper()
        if "AMD" in output or "RADEON" in output:
            return "AMD"
        if "NVIDIA" in output or "GEFORCE" in output or "RTX" in output:
            return "NVIDIA"
        if "INTEL" in output or "ARC" in output or "UHD" in output:
            return "INTEL"
    except Exception:
        pass
    return "UNKNOWN"


def get_available_providers() -> List[str]:
    """Return the list of ONNX Runtime execution providers actually available."""
    return ort.get_available_providers()


def select_providers() -> Tuple[List[str], dict]:
    """
    Select the best execution providers in priority order.
    Returns (provider_list, metadata_dict).
    """
    available = set(get_available_providers())
    selected: List[str] = []
    meta = {
        "npu_detected": False,
        "gpu_vendor": "UNKNOWN",
        "selected_device": "CPU",
    }

    logger.info("Available ONNX Runtime providers: %s", available)

    # 1. Check for AMD NPU
    if "VitisAIExecutionProvider" in available and _detect_amd_npu():
        selected.append("VitisAIExecutionProvider")
        meta["npu_detected"] = True
        meta["selected_device"] = "AMD Ryzen AI NPU"
        logger.info("AMD Ryzen AI NPU detected - using VitisAIExecutionProvider")

    # 2. DirectML works on AMD, NVIDIA, and Intel GPUs
    if "DmlExecutionProvider" in available:
        selected.append("DmlExecutionProvider")
        meta["gpu_vendor"] = _detect_gpu_vendor()
        if meta["selected_device"] == "CPU":
            meta["selected_device"] = f"GPU ({meta['gpu_vendor']}) via DirectML"
        logger.info("DirectML available - GPU vendor: %s", meta["gpu_vendor"])

    # 3. CPU is always the final fallback
    selected.append("CPUExecutionProvider")

    if not selected or selected == ["CPUExecutionProvider"]:
        meta["selected_device"] = "CPU (fallback)"
        logger.warning("No accelerator found. Running on CPU only.")

    logger.info("Final provider chain: %s", selected)
    logger.info("Primary device: %s", meta["selected_device"])
    return selected, meta


def create_session(model_path: str) -> Tuple[ort.InferenceSession, dict]:
    """Create an ONNX InferenceSession with the best available providers."""
    providers, meta = select_providers()
    sess_options = ort.SessionOptions()
    sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    sess_options.log_severity_level = 3  # Suppress verbose logs

    session = ort.InferenceSession(
        model_path,
        sess_options=sess_options,
        providers=providers,
    )
    active = session.get_providers()
    meta["active_providers"] = active
    logger.info("Session created. Active providers: %s", active)
    return session, meta
