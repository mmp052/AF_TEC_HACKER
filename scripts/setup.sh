#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[setup] subindo Juice Shop..."
bash lab/reset.sh

echo "[setup] clonando SecLists (shallow)..."
if [ ! -d wordlists/SecLists ]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists wordlists/SecLists
fi


echo "[setup] deps python (user)..."
python3 -m pip install --break-system-packages -r requirements.txt || \
python3 -m pip install rich pydantic httpx pyyaml

echo "[setup] baixando modelo qwen3:4b (se nao houver)..."
ollama pull qwen3:4b || true

echo "[setup] pronto. Proximos passos:"
echo "  python3 main.py check"
echo "  python3 main.py run --file exemplo.yaml"
