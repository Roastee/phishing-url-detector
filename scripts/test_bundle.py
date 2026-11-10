#!/usr/bin/env python
"""Test the Vercel deployment bundle by copying only deployed files to a temp dir and running tests."""

import os
import shutil
import tempfile
import subprocess
import sys
import json

def create_bundle():
    """Create a temp directory with only the files Vercel would deploy."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    temp_dir = tempfile.mkdtemp(prefix="vercel_bundle_")
    
    print(f"Creating bundle in {temp_dir}")
    
    # Files/dirs to include (respecting .vercelignore)
    include_patterns = [
        "index.py",
        "api/",
        "src/",
        "models/",
        "requirements.txt",
        ".python-version",
        ".vercelignore",
        "README.md",
        "tests/",
    ]
    
    # Copy included files
    for pattern in include_patterns:
        src = os.path.join(repo_root, pattern)
        dst = os.path.join(temp_dir, pattern)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                '*.pyc', '__pycache__', '*.pkl', '*.joblib'
            ))
        elif os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    
    # Remove excluded files from models/
    models_dir = os.path.join(temp_dir, "models")
    for f in os.listdir(models_dir):
        if f.endswith(('.pkl', '.joblib')):
            os.remove(os.path.join(models_dir, f))
    
    return temp_dir

def run_tests(bundle_dir):
    """Run tests from the bundle directory."""
    env = os.environ.copy()
    env['PYTHONPATH'] = bundle_dir
    
    # Install dependencies
    print("Installing dependencies...")
    result = subprocess.run([
        sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
    ], cwd=bundle_dir, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        print(f"pip install failed: {result.stderr}")
        return False
    
    # Run pytest
    print("Running tests...")
    result = subprocess.run([
        sys.executable, "-m", "pytest", "tests/test_bundle.py", "-q", "-W", "error::UserWarning"
    ], cwd=bundle_dir, capture_output=True, text=True, env=env)
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    return result.returncode == 0

def main():
    bundle_dir = None
    try:
        bundle_dir = create_bundle()
        success = run_tests(bundle_dir)
        if success:
            print("\n✓ All bundle tests passed!")
        else:
            print("\n✗ Bundle tests failed!")
            return 1
    finally:
        if bundle_dir and os.path.exists(bundle_dir):
            shutil.rmtree(bundle_dir)
            print(f"Cleaned up {bundle_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())