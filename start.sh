#!/usr/bin/env bash
# Script khởi chạy nhanh CrowdSec Decision Manager Web Dashboard

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-5000}"

echo "=========================================================="
echo "    CrowdSec Decisions Manager - Web Dashboard            "
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[!] Bạn đang chạy mà không có quyền root."
    echo "[!] Đang thử chuyển sang sudo..."
    exec sudo python3 "$DIR/app.py" --port "$PORT" --host 0.0.0.0
else
    exec python3 "$DIR/app.py" --port "$PORT" --host 0.0.0.0
fi

