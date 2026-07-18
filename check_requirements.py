"""
TrustField — Dependency Checker
Run: python check_requirements.py
"""

import importlib
import subprocess
import sys

# ─────────────────────────────────────────────────────────────
# Map: friendly name → (import name, pip package name)
# ─────────────────────────────────────────────────────────────
REQUIREMENTS = {
    # ── Backend / API ──────────────────────────────────────────
    "FastAPI":              ("fastapi",          "fastapi"),
    "Uvicorn":              ("uvicorn",          "uvicorn"),
    "Pydantic":             ("pydantic",         "pydantic"),
    "Python-dotenv":        ("dotenv",           "python-dotenv"),
    "Httpx":                ("httpx",            "httpx"),

    # ── Cloud SDKs ─────────────────────────────────────────────
    "Boto3 (AWS)":          ("boto3",            "boto3"),
    "Azure Identity":       ("azure.identity",   "azure-identity"),
    "Azure MGMT Resource":  ("azure.mgmt.resource", "azure-mgmt-resource"),
    "Google Cloud IAM":     ("google.cloud.iam",    "google-cloud-iam"),
    "Kubernetes Client":    ("kubernetes",       "kubernetes"),

    # ── Graph / Neo4j ──────────────────────────────────────────
    "Neo4j Driver":         ("neo4j",            "neo4j"),
    "NetworkX":             ("networkx",         "networkx"),

    # ── ML / AI ───────────────────────────────────────────────
    "Scikit-learn":         ("sklearn",          "scikit-learn"),
    "NumPy":                ("numpy",            "numpy"),
    "Pandas":               ("pandas",           "pandas"),
    "PyTorch":              ("torch",            "torch"),
    "PyTorch Geometric":    ("torch_geometric",  "torch-geometric"),

    # ── Database / Storage ─────────────────────────────────────
    "SQLAlchemy":           ("sqlalchemy",       "sqlalchemy"),
    "Psycopg2":             ("psycopg2",         "psycopg2-binary"),
    "PyMongo":              ("pymongo",          "pymongo"),
    "Redis":                ("redis",            "redis"),

    # ── Security ───────────────────────────────────────────────
    "Cryptography":         ("cryptography",     "cryptography"),
    "PyJWT":                ("jwt",              "PyJWT"),
    "Passlib":              ("passlib",          "passlib"),

    # ── Testing ────────────────────────────────────────────────
    "Pytest":               ("pytest",           "pytest"),
    "Moto (AWS mock)":      ("moto",             "moto"),
    "Pytest-asyncio":       ("pytest_asyncio",   "pytest-asyncio"),
    "HTTPX (test client)":  ("httpx",            "httpx"),

    # ── Utilities ──────────────────────────────────────────────
    "Python-Jose":          ("jose",             "python-jose"),
    "Celery":               ("celery",           "celery"),
    "Structlog":            ("structlog",        "structlog"),
}

# ANSI colours
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def get_version(import_name: str) -> str:
    """Try to get the installed version of a package."""
    try:
        mod = importlib.import_module(import_name.split(".")[0])
        return getattr(mod, "__version__", "installed")
    except Exception:
        return "?"

def check_python_version():
    major, minor = sys.version_info[:2]
    ok = (major == 3 and minor >= 10)
    status = f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"
    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"  {BOLD}Python Version{RESET}")
    print(f"{'─'*55}")
    label = f"Python {major}.{minor}"
    req   = "3.10+"
    print(f"  {status}  {label:<30} (required: {req})")
    if not ok:
        print(f"  {YELLOW}↳  Please upgrade to Python 3.10 or later.{RESET}")
    return ok

def check_packages():
    passed, failed = [], []

    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"  {BOLD}Python Packages{RESET}")
    print(f"{'─'*55}")

    for name, (import_name, pip_name) in REQUIREMENTS.items():
        try:
            importlib.import_module(import_name)
            version = get_version(import_name)
            print(f"  {GREEN}✔{RESET}  {name:<30} {CYAN}{version}{RESET}")
            passed.append(name)
        except ImportError:
            print(f"  {RED}✘{RESET}  {name:<30} {RED}NOT INSTALLED{RESET}  → pip install {pip_name}")
            failed.append((name, pip_name))

    return passed, failed

def check_node():
    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"  {BOLD}Node.js & npm{RESET}")
    print(f"{'─'*55}")
    results = []
    for cmd, label, required in [
        ("node --version", "Node.js", "18 or 20 LTS"),
        ("npm --version",  "npm",     "any recent"),
    ]:
        try:
            out = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.DEVNULL
            ).decode().strip()
            print(f"  {GREEN}✔{RESET}  {label:<30} {CYAN}{out}{RESET}  (required: {required})")
            results.append(True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"  {RED}✘{RESET}  {label:<30} {RED}NOT FOUND{RESET}")
            results.append(False)
    return results

def summary(py_ok, passed, failed, node_results):
    total = 1 + len(REQUIREMENTS) + 2          # python + packages + node/npm
    ok    = int(py_ok) + len(passed) + sum(node_results)
    pct   = int(ok / total * 100)

    print(f"\n{BOLD}{'═'*55}{RESET}")
    print(f"  {BOLD}Summary{RESET}")
    print(f"{'═'*55}")
    print(f"  Checks passed : {GREEN}{ok}{RESET} / {total}  ({pct}%)")

    if failed:
        print(f"\n  {YELLOW}Missing packages — install with:{RESET}")
        pip_list = " ".join(pip for _, pip in failed)
        print(f"\n    pip install {pip_list}\n")
    else:
        print(f"\n  {GREEN}{BOLD}All packages installed — TrustField is ready! 🚀{RESET}\n")

if __name__ == "__main__":
    print(f"\n{BOLD}{CYAN}  TrustField · Dependency Checker{RESET}")

    py_ok              = check_python_version()
    passed, failed     = check_packages()
    node_results       = check_node()

    summary(py_ok, passed, failed, node_results)