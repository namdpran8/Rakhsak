"""
RAKSHAK - Model Downloader
Downloads quantized Phi-3.5-mini-instruct ONNX model for local threat analysis.
Uses INT4 AWQ quantization for fast inference on GPU via DirectML.
"""

import os
import sys
import argparse


MODEL_REPO = "microsoft/Phi-3.5-mini-instruct-onnx"
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models", "phi3.5-mini")

# Variants mapped to actual HuggingFace repo subfolder names
VARIANTS = {
    "gpu-int4":  "gpu/gpu-int4-awq-block-128",
    "cpu-int4":  "cpu_and_mobile/cpu-int4-awq-block-128-acc-level-4",
}

DEFAULT_VARIANT = "gpu-int4"


def download_model(variant: str = DEFAULT_VARIANT, output_dir: str = MODEL_DIR):
    """Download the specified model variant from Hugging Face."""
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("[!] huggingface-hub is required. Install with:")
        print("    pip install huggingface-hub")
        sys.exit(1)

    subfolder = VARIANTS.get(variant)
    if subfolder is None:
        print(f"[!] Unknown variant '{variant}'. Available: {list(VARIANTS.keys())}")
        sys.exit(1)

    print(f"[*] Downloading Phi-3.5-mini-instruct ONNX ({variant})...")
    print(f"[*] Repository : {MODEL_REPO}")
    print(f"[*] Subfolder  : {subfolder}")
    print(f"[*] Destination: {output_dir}")
    print()

    os.makedirs(output_dir, exist_ok=True)

    try:
        path = snapshot_download(
            MODEL_REPO,
            allow_patterns=[f"{subfolder}/*"],
            local_dir=output_dir,
        )
        # The files end up in output_dir/directml/directml-int4-awq-block-128/
        model_path = os.path.join(output_dir, subfolder)
        if os.path.isdir(model_path):
            print(f"\n[+] Model downloaded successfully to: {model_path}")
            print(f"[+] Contents:")
            for f in sorted(os.listdir(model_path)):
                size_mb = os.path.getsize(os.path.join(model_path, f)) / (1024 * 1024)
                print(f"    {f:40s} {size_mb:>8.1f} MB")
        else:
            print(f"\n[+] Downloaded to: {path}")

        return model_path

    except Exception as exc:
        print(f"\n[!] Download failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download ONNX model for Rakshak")
    parser.add_argument(
        "--variant", default=DEFAULT_VARIANT,
        choices=list(VARIANTS.keys()),
        help=f"Model variant to download (default: {DEFAULT_VARIANT})",
    )
    parser.add_argument(
        "--output", default=MODEL_DIR,
        help=f"Output directory (default: {MODEL_DIR})",
    )
    args = parser.parse_args()
    download_model(variant=args.variant, output_dir=args.output)
