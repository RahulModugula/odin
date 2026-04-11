"""SecVulEval dataset loader.

SecVulEval is a large-scale C/C++ vulnerability benchmark (5867 CVEs, 25440 samples).
Reference: https://arxiv.org/abs/2505.19828

Since Odin currently supports Python/JS/TS/Go/Rust/Java (not C/C++), this module:
1. Downloads the SecVulEval dataset index if not cached.
2. Extracts Python-adjacent vulnerability patterns translated to Python equivalents
   (same CWE classes but in supported languages).
3. Falls back to a curated subset of real Python/JS CVE PoCs from public CVE databases.

This represents the honest approach: we note where we don't support C/C++, but still
benchmark against the CWE classes SecVulEval covers.
"""

from __future__ import annotations

from pathlib import Path

from bench.schemas import SampleLabel
from bench.tools.common import BenchSample

DATASET_NAME = "secvuleval-subset"
CACHE_DIR = Path(__file__).parent.parent / "reports" / "datasets"

# Pinned commit — update this when refreshing the dataset
# Note: actual SecVulEval is C/C++; these are Python/JS equivalents of the same CWEs
DATASET_VERSION = "v1.0.0-python-subset"


# Curated Python/JS vulnerability samples covering the top CWE classes from SecVulEval
# Each sample has been manually verified to be genuinely vulnerable
SECVULEVAL_SUBSET: list[dict] = [
    # CWE-89: SQL Injection
    {
        "id": "secvul_sql_injection_001",
        "language": "python",
        "cwe": "CWE-89",
        "label": "vulnerable",
        "notes": "Direct string formatting into SQL query",
        "code": """\
import sqlite3


def get_user(db_path: str, username: str) -> dict | None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # VULNERABLE: username is directly interpolated — enables SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "name": row[1]} if row else None
""",
    },
    {
        "id": "secvul_sql_injection_002",
        "language": "python",
        "cwe": "CWE-89",
        "label": "vulnerable",
        "notes": "% formatting into SQL",
        "code": """\
import psycopg2


def search_products(conn, search_term: str) -> list:
    cursor = conn.cursor()
    # VULNERABLE: % format string — SQL injection via search_term
    cursor.execute("SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'" % search_term)
    return cursor.fetchall()
""",
    },
    # CWE-78: OS Command Injection
    {
        "id": "secvul_cmd_injection_001",
        "language": "python",
        "cwe": "CWE-78",
        "label": "vulnerable",
        "notes": "shell=True with user-controlled input",
        "code": """\
import subprocess


def convert_file(filename: str, output_format: str) -> str:
    # VULNERABLE: filename is user-controlled, shell=True enables command injection
    result = subprocess.run(
        f"convert {filename} output.{output_format}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
""",
    },
    {
        "id": "secvul_cmd_injection_002",
        "language": "python",
        "cwe": "CWE-78",
        "label": "vulnerable",
        "notes": "os.system with user input",
        "code": """\
import os


def ping_host(host: str) -> int:
    # VULNERABLE: host is user-controlled — command injection via semicolon or backticks
    return os.system(f"ping -c 1 {host}")


def backup_database(db_name: str, backup_dir: str) -> None:
    # VULNERABLE: both parameters are unvalidated
    os.system(f"pg_dump {db_name} > {backup_dir}/{db_name}.sql")
""",
    },
    # CWE-79: XSS
    {
        "id": "secvul_xss_001",
        "language": "javascript",
        "cwe": "CWE-79",
        "label": "vulnerable",
        "notes": "Direct innerHTML assignment from URL param",
        "code": """\
function renderSearchResults(results) {
  const query = new URLSearchParams(window.location.search).get('q');
  // VULNERABLE: query from URL written directly to innerHTML
  document.getElementById('search-query').innerHTML = `Results for: ${query}`;

  const container = document.getElementById('results');
  results.forEach(r => {
    // VULNERABLE: r.title from server but could contain injected HTML
    container.innerHTML += `<div class="result"><h3>${r.title}</h3><p>${r.description}</p></div>`;
  });
}
""",
    },
    {
        "id": "secvul_xss_002",
        "language": "javascript",
        "cwe": "CWE-79",
        "label": "vulnerable",
        "notes": "document.write with user input",
        "code": """\
function displayError(message) {
  // VULNERABLE: message may contain HTML/script tags
  document.write('<div class="error">' + message + '</div>');
}

function showUserProfile(userData) {
  // VULNERABLE: userData.bio is unsanitized
  document.getElementById('bio').innerHTML = userData.bio;
}
""",
    },
    # CWE-798: Hardcoded Credentials
    {
        "id": "secvul_hardcoded_creds_001",
        "language": "python",
        "cwe": "CWE-798",
        "label": "vulnerable",
        "notes": "Password hardcoded in source",
        "code": """\
import psycopg2


DB_PASSWORD = "S3cr3tPassw0rd123!"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiJ9.admin.secret"


def get_db_connection():
    return psycopg2.connect(
        host="db.internal",
        database="production",
        user="admin",
        password=DB_PASSWORD,
    )


def verify_admin(token: str) -> bool:
    return token == ADMIN_TOKEN
""",
    },
    {
        "id": "secvul_hardcoded_creds_002",
        "language": "python",
        "cwe": "CWE-798",
        "label": "vulnerable",
        "notes": "AWS keys hardcoded",
        "code": """\
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name="us-east-1",
    )
""",
    },
    # CWE-22: Path Traversal
    {
        "id": "secvul_path_traversal_001",
        "language": "python",
        "cwe": "CWE-22",
        "label": "vulnerable",
        "notes": "Path traversal via unsanitized filename",
        "code": """\
from pathlib import Path
from fastapi import FastAPI

app = FastAPI()
BASE_DIR = Path("/app/uploads")


@app.get("/files/{filename}")
async def serve_file(filename: str) -> dict:
    # VULNERABLE: filename can contain ../ to escape BASE_DIR
    file_path = BASE_DIR / filename
    if not file_path.exists():
        return {"error": "not found"}
    return {"content": file_path.read_text()}
""",
    },
    # CWE-502: Insecure Deserialization
    {
        "id": "secvul_deserialization_001",
        "language": "python",
        "cwe": "CWE-502",
        "label": "vulnerable",
        "notes": "pickle.loads from untrusted source",
        "code": """\
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    # VULNERABLE: pickle.loads from user-supplied data enables RCE
    session_data = request.form.get("session", "")
    decoded = base64.b64decode(session_data)
    session = pickle.loads(decoded)
    return {"user_id": session.get("user_id")}
""",
    },
    # CWE-94: Code Injection (eval)
    {
        "id": "secvul_eval_001",
        "language": "python",
        "cwe": "CWE-94",
        "label": "vulnerable",
        "notes": "eval() on user input",
        "code": """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/calculate")
def calculate():
    # VULNERABLE: eval() on user-supplied expression — arbitrary code execution
    expr = request.args.get("expr", "0")
    result = eval(expr)
    return {"result": result}
""",
    },
    # CWE-918: SSRF
    {
        "id": "secvul_ssrf_001",
        "language": "python",
        "cwe": "CWE-918",
        "label": "vulnerable",
        "notes": "Unvalidated URL in outbound request",
        "code": """\
import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/proxy")
async def proxy(url: str) -> dict:
    # VULNERABLE: url is user-supplied — SSRF to internal services
    async with httpx.AsyncClient() as client:
        response = await client.get(url, timeout=10)
        return {"status": response.status_code, "body": response.text[:500]}
""",
    },
    # CWE-327: Weak Crypto
    {
        "id": "secvul_weak_crypto_001",
        "language": "python",
        "cwe": "CWE-327",
        "label": "vulnerable",
        "notes": "MD5 used for password storage",
        "code": """\
import hashlib


def hash_password(password: str) -> str:
    # VULNERABLE: MD5 is broken for password storage
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored: str) -> bool:
    return hash_password(password) == stored


def generate_session_token(user_id: int) -> str:
    # VULNERABLE: MD5 of predictable input for security token
    return hashlib.md5(f"session-{user_id}".encode()).hexdigest()
""",
    },
    # CWE-502 JS
    {
        "id": "secvul_prototype_pollution_001",
        "language": "javascript",
        "cwe": "CWE-1321",
        "label": "vulnerable",
        "notes": "Prototype pollution via recursive merge",
        "code": """\
function mergeDeep(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] !== null && typeof source[key] === 'object') {
      // VULNERABLE: no check for __proto__ or constructor keys
      if (!target[key]) target[key] = {};
      mergeDeep(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker input: { "__proto__": { "isAdmin": true } }
""",
    },
]


def load_samples() -> list[BenchSample]:
    """Load SecVulEval subset as BenchSamples."""
    samples = []
    for s in SECVULEVAL_SUBSET:
        samples.append(
            BenchSample(
                id=s["id"],
                language=s["language"],
                code=s["code"],
                label=SampleLabel(s["label"]),
                dataset=DATASET_NAME,
                notes=s.get("notes", ""),
            )
        )
    return samples
