import os
from huggingface_hub import hf_hub_download

REPO_ID = "Xenova/distilbert-base-multilingual-cased-ner-hrl"
TARGET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "distilbert-multilingual-ner-int8")

FILES = [
    "onnx/model_quantized.onnx",
    "vocab.txt",
    "config.json",
    "tokenizer_config.json",
]

def main():
    os.makedirs(TARGET_DIR, exist_ok=True)
    print(f"Downloading {REPO_ID} to {TARGET_DIR}...")
    for rel_path in FILES:
        local_path = hf_hub_download(
            repo_id=REPO_ID,
            filename=rel_path,
            local_dir=TARGET_DIR,
        )
        size_mb = os.path.getsize(local_path) / (1024 * 1024)
        print(f"  [OK] {rel_path} ({size_mb:.2f} MB)")
    print("Done.")

if __name__ == "__main__":
    main()
