"""Vercel serverless function entry point for FastAPI."""

import sys
from pathlib import Path

# Ensure project root and src/ are in sys.path
root_dir = Path(__file__).resolve().parents[1]
src_dir = root_dir / "src"

if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from api.main import app  # noqa: E402, F401

