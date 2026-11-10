"""Vercel entry point for the FastAPI app."""

import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from api.main import app

# Vercel expects the FastAPI instance to be named 'app'
# This is already the case in api/main.py