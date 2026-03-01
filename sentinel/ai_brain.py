"""
RAKSHAK - AI Brain Module
Uses a quantized Phi-3.5-mini ONNX model via onnxruntime-genai for threat analysis.
Falls back to a rule-based heuristic when the model is unavailable.

Model hierarchy:
  1. onnxruntime-genai + Phi-3.5-mini ONNX (best: GPU-accelerated generation)
  2. Rule-based engine (always available, no model needed)
"""

import logging
import os
import json
import time
from typing import Optional

logger = logging.getLogger("Rakshak.Brain")

# ---------------------------------------------------------------------------
# Try to import onnxruntime-genai (preferred for text generation)
# ---------------------------------------------------------------------------
HAS_GENAI = False
try:
    import onnxruntime_genai as og
    HAS_GENAI = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Rule-based fallback (always available, no model needed)
# ---------------------------------------------------------------------------
THREAT_RULES = {
    "fake_malware":  ("MALICIOUS", "Process name matches a known malware test pattern. "
                      "Likely a simulated threat or penetration test tool."),
    "mimikatz":      ("CRITICAL",  "Mimikatz-class credential harvesting tool detected. "
                      "Capable of extracting plaintext passwords from memory."),
    "cobalt":        ("CRITICAL",  "Cobalt Strike beacon signature. Command-and-control "
                      "framework commonly used in advanced persistent threats."),
    "keylogger":     ("HIGH",      "Keystroke capture utility detected. Could be exfiltrating "
                      "credentials and sensitive user input."),
    "cryptominer":   ("HIGH",      "Cryptocurrency mining process detected. Unauthorized "
                      "resource consumption drains power and degrades performance."),
    "ransomware":    ("CRITICAL",  "Ransomware behavior pattern. May be encrypting user files "
                      "for extortion purposes."),
    "reverse_shell": ("CRITICAL",  "Reverse shell detected. An attacker may have remote "
                      "command execution on this machine."),
    "payload":       ("HIGH",      "Generic payload dropper detected. Could be staging "
                      "additional malicious components."),
}


def rule_based_analysis(process_name: str, reason: str, details: dict) -> dict:
    """Produce a threat analysis using keyword rules (no AI model required)."""
    name_lower = process_name.lower()
    for keyword, (level, explanation) in THREAT_RULES.items():
        if keyword in name_lower:
            return {
                "verdict": level,
                "explanation": explanation,
                "recommendation": _recommendation(level),
                "engine": "rule-based",
            }

    # Filesystem anomaly
    if "rapid file creation" in reason.lower():
        count = details.get("file_count", 0)
        return {
            "verdict": "HIGH" if count > 50 else "MEDIUM",
            "explanation": (f"Burst of {count} files created in a short window. "
                           "This pattern is consistent with ransomware encryption, "
                           "malware payload drops, or a fork-bomb staging area."),
            "recommendation": "Isolate the directory. Identify the parent process and terminate if unauthorized.",
            "engine": "rule-based",
        }

    # CPU spike
    if "cpu" in reason.lower():
        return {
            "verdict": "MEDIUM",
            "explanation": ("Abnormal CPU consumption may indicate cryptojacking, "
                           "a denial-of-service loop, or resource abuse."),
            "recommendation": "Investigate the process tree. Throttle or kill if no legitimate workload is running.",
            "engine": "rule-based",
        }

    return {
        "verdict": "LOW",
        "explanation": "No specific threat signature matched. Monitor for recurrence.",
        "recommendation": "Continue monitoring. No immediate action required.",
        "engine": "rule-based",
    }


def _recommendation(level: str) -> str:
    recs = {
        "CRITICAL": "IMMEDIATELY terminate the process and isolate the host from the network.",
        "HIGH": "Terminate the process. Conduct a forensic scan on affected files.",
        "MEDIUM": "Flag for review. Restrict the process's network and filesystem access.",
        "MALICIOUS": "Terminate the process. This is a confirmed threat simulation.",
    }
    return recs.get(level, "Continue monitoring.")


def analyze_behavioral(anomaly_type: str, process_name: str,
                       baseline: float, observed: float, zscore: float,
                       parent_chain: list) -> dict:
    """Analyze a behavioral anomaly (from the BehavioralDetector)."""
    chain_str = " -> ".join(parent_chain[:3]) if parent_chain else "unknown"

    severity = "HIGH" if abs(zscore) >= 5.0 else "MEDIUM"

    type_descriptions = {
        "cpu_spike": (
            f"Process '{process_name}' CPU usage jumped to {observed:.1f}% "
            f"(baseline: {baseline:.1f}%, z-score: {zscore:.1f}). "
            f"This deviation suggests cryptojacking, a tight infinite loop, "
            f"or resource abuse. Process tree: {chain_str}."
        ),
        "memory_spike": (
            f"Memory consumption by '{process_name}' surged to {observed:.1f}% "
            f"(baseline: {baseline:.1f}%). Possible memory leak weaponization, "
            f"heap spray attack, or data staging in RAM before exfiltration."
        ),
        "io_write_spike": (
            f"Disk write rate for '{process_name}' spiked to {observed:.1f} MB "
            f"(baseline: {baseline:.1f} MB). Pattern consistent with ransomware "
            f"encryption, bulk data staging, or log wiping."
        ),
        "io_read_spike": (
            f"Disk read burst by '{process_name}': {observed:.1f} MB "
            f"(baseline: {baseline:.1f} MB). May indicate data harvesting, "
            f"credential file enumeration, or database exfiltration."
        ),
        "network_spike": (
            f"'{process_name}' opened {observed:.0f} network connections "
            f"(baseline: {baseline:.0f}). Could indicate C2 beacon activity, "
            f"port scanning, or data exfiltration over multiple channels."
        ),
        "threads_spike": (
            f"Thread count for '{process_name}' jumped to {observed:.0f} "
            f"(baseline: {baseline:.0f}). Possible fork bomb preparation, "
            f"process injection, or DLL injection staging."
        ),
        "spawn_storm": (
            f"'{process_name}' spawned {observed:.0f} child processes in one scan window. "
            f"This is characteristic of fork bombs, worm propagation, "
            f"or automated exploit frameworks."
        ),
    }

    explanation = type_descriptions.get(anomaly_type,
        f"Behavioral anomaly '{anomaly_type}' in '{process_name}': "
        f"observed={observed:.1f}, baseline={baseline:.1f}, z={zscore:.1f}")

    return {
        "verdict": severity,
        "explanation": explanation,
        "recommendation": _recommendation(severity),
        "engine": "behavioral-zscore",
        "zscore": round(zscore, 2),
        "anomaly_type": anomaly_type,
    }


def analyze_scan_finding(rule_name: str, severity: str, category: str,
                         description: str, file_path: str,
                         line_number: int, matched_text: str) -> dict:
    """Analyze a code scan finding."""
    return {
        "verdict": severity,
        "explanation": (f"Code scan detected '{rule_name}' at {file_path}:{line_number}. "
                       f"{description}. Matched pattern: '{matched_text[:60]}'"),
        "recommendation": _recommendation(severity),
        "engine": "code-scanner",
        "category": category,
    }


# ---------------------------------------------------------------------------
# Model discovery
# ---------------------------------------------------------------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models", "phi3.5-mini")

# Preferred model paths in order of preference
_MODEL_SEARCH_PATHS = [
    # onnxruntime-genai style (folder with genai_config.json)
    os.path.join(MODEL_DIR, "gpu", "gpu-int4-awq-block-128"),
    os.path.join(MODEL_DIR, "cpu_and_mobile", "cpu-int4-awq-block-128-acc-level-4"),
    # Direct model dir
    MODEL_DIR,
]


def _find_model_dir() -> Optional[str]:
    """Find a valid onnxruntime-genai model directory."""
    for path in _MODEL_SEARCH_PATHS:
        config = os.path.join(path, "genai_config.json")
        if os.path.isfile(config):
            return path
    return None


# ---------------------------------------------------------------------------
# AI Brain (onnxruntime-genai + Phi-3.5-mini)
# ---------------------------------------------------------------------------
class AIBrain:
    """
    Wraps a quantized Phi-3.5-mini ONNX model for threat-intent analysis.
    Uses onnxruntime-genai for proper autoregressive text generation.
    Falls back to rule_based_analysis when the model is absent.
    """

    def __init__(self, providers: Optional[list] = None):
        self.providers = providers or ["CPUExecutionProvider"]
        self.model = None
        self.tokenizer = None
        self.model_loaded = False
        self.model_path = None
        self._inference_count = 0
        self._total_inference_ms = 0.0
        self._try_load()

    def _try_load(self):
        if not HAS_GENAI:
            logger.info("onnxruntime-genai not installed - using rule-based engine only")
            logger.info("Install with: pip install onnxruntime-genai-directml")
            return

        model_dir = _find_model_dir()
        if model_dir is None:
            logger.info("No ONNX model found in %s - using rule-based engine only", MODEL_DIR)
            logger.info("Download with: python -m sentinel.download_model")
            return

        try:
            logger.info("Loading model from %s ...", model_dir)
            self.model = og.Model(model_dir)
            self.tokenizer = og.Tokenizer(self.model)
            self.model_path = model_dir
            self.model_loaded = True
            logger.info("Phi-3.5-mini ONNX model loaded successfully")
        except Exception as exc:
            logger.error("Failed to load ONNX model: %s", exc)
            self.model = None
            self.tokenizer = None

    def analyze(self, process_name: str, reason: str, details: dict) -> dict:
        """Analyze a threat event. Uses AI model if available, else rules."""
        if self.model_loaded and self.model and self.tokenizer:
            return self._ai_analysis(process_name, reason, details)
        return rule_based_analysis(process_name, reason, details)

    def _ai_analysis(self, process_name: str, reason: str, details: dict) -> dict:
        """Run the Phi-3.5-mini model to generate a natural-language threat analysis."""
        prompt = self._build_prompt(process_name, reason, details)

        try:
            input_tokens = self.tokenizer.encode(prompt)

            params = og.GeneratorParams(self.model)
            params.set_search_options(
                max_length=256,
                temperature=0.3,
                top_p=0.9,
                do_sample=False,
            )
            params.input_ids = input_tokens

            start = time.perf_counter()
            output_tokens = self.model.generate(params)
            elapsed = time.perf_counter() - start

            response_text = self.tokenizer.decode(output_tokens[0])

            # Track inference metrics
            self._inference_count += 1
            self._total_inference_ms += elapsed * 1000

            # Strip the prompt from the response if echoed back
            if response_text.startswith(prompt):
                response_text = response_text[len(prompt):]

            return {
                "verdict": self._extract_verdict(response_text),
                "explanation": response_text.strip()[:500],
                "recommendation": self._extract_recommendation(response_text),
                "engine": "phi3.5-mini-onnx",
                "inference_ms": round(elapsed * 1000, 1),
            }
        except Exception as exc:
            logger.error("AI inference failed, falling back to rules: %s", exc)
            result = rule_based_analysis(process_name, reason, details)
            result["fallback_reason"] = str(exc)
            return result

    def get_inference_metrics(self) -> dict:
        """Return AI inference performance metrics."""
        avg_ms = (self._total_inference_ms / self._inference_count
                  if self._inference_count > 0 else 0.0)
        return {
            "model_loaded": self.model_loaded,
            "engine": "phi3.5-mini-onnx" if self.model_loaded else "rule-based",
            "model_path": self.model_path,
            "inference_count": self._inference_count,
            "avg_inference_ms": round(avg_ms, 1),
            "total_inference_ms": round(self._total_inference_ms, 1),
        }

    @staticmethod
    def _build_prompt(process_name: str, reason: str, details: dict) -> str:
        detail_str = json.dumps(details, indent=2, default=str)
        return (
            "<|system|>\n"
            "You are a cybersecurity threat analyst for an endpoint detection system. "
            "Analyze the following process event and determine if it is malicious, suspicious, or benign. "
            "Respond with:\n"
            "SEVERITY: CRITICAL/HIGH/MEDIUM/LOW\n"
            "EXPLANATION: One paragraph analysis\n"
            "RECOMMENDATION: One sentence action item\n"
            "<|end|>\n"
            "<|user|>\n"
            f"Process: {process_name}\n"
            f"Alert Reason: {reason}\n"
            f"Details:\n{detail_str}\n"
            "<|end|>\n"
            "<|assistant|>\n"
        )

    @staticmethod
    def _extract_verdict(text: str) -> str:
        text_upper = text.upper()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if level in text_upper:
                return level
        return "MEDIUM"

    @staticmethod
    def _extract_recommendation(text: str) -> str:
        for marker in ("RECOMMENDATION:", "Recommendation:", "Action:", "Remediation:"):
            if marker in text:
                return text.split(marker, 1)[1].strip().split("\n")[0]
        return "Investigate and monitor the process."
