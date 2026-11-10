"""Syntax tests: ensure all .py files compile without errors."""
import ast
import py_compile
import os

def test_syntax_app():
    """Test all .py files in app/ compile."""
    app_dir = os.path.join(os.path.dirname(__file__), "..", "app")
    for fname in os.listdir(app_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(app_dir, fname)
            py_compile.compile(fpath, doraise=True)

def test_syntax_src():
    """Test all .py files in src/ compile."""
    src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
    for root, dirs, files in os.walk(src_dir):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                py_compile.compile(fpath, doraise=True)

def test_syntax_api():
    """Test all .py files in api/ compile."""
    api_dir = os.path.join(os.path.dirname(__file__), "..", "api")
    for fname in os.listdir(api_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(api_dir, fname)
            py_compile.compile(fpath, doraise=True)

def test_syntax_tests():
    """Test all .py files in tests/ compile."""
    tests_dir = os.path.dirname(__file__)
    for fname in os.listdir(tests_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(tests_dir, fname)
            py_compile.compile(fpath, doraise=True)

def test_syntax_scripts():
    """Test all .py files in scripts/ compile."""
    scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
    if os.path.exists(scripts_dir):
        for fname in os.listdir(scripts_dir):
            if fname.endswith(".py"):
                fpath = os.path.join(scripts_dir, fname)
                py_compile.compile(fpath, doraise=True)

def test_ast_parse_all():
    """Verify all .py files can be parsed by ast (no syntax errors)."""
    project_root = os.path.join(os.path.dirname(__file__), "..")
    for subdir in ["app", "src", "api", "tests", "scripts"]:
        dirpath = os.path.join(project_root, subdir)
        if not os.path.exists(dirpath):
            continue
        for root, dirs, files in os.walk(dirpath):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    with open(fpath, encoding="utf-8") as f:
                        source = f.read()
                    ast.parse(source, filename=fpath)