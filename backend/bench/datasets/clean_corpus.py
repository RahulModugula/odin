"""Clean code corpus — 60 idiomatic snippets that MUST produce zero security findings.

Each sample is carefully written to be secure, idiomatic, and representative of
real production code. A tool with good precision should flag none of these.

Format:
  {"id": str, "language": str, "code": str, "notes": str}

Design principles:
- Parameterized queries (not string interpolation) for SQL
- No hardcoded credentials — env vars only
- No eval/exec/subprocess(shell=True)
- Proper error handling without broad bare-excepts
- Type-annotated where idiomatic
- No mutable defaults
- No innerHTML — DOM manipulation via textContent or framework
"""

from __future__ import annotations

CLEAN_SAMPLES: list[dict] = [
    # ─────────────────────── PYTHON (20 samples) ────────────────────────────
    {
        "id": "py_dataclass_clean",
        "language": "python",
        "notes": "Dataclass with type hints, no mutable defaults",
        "code": """\
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class UserProfile:
    user_id: int
    username: str
    email: str
    roles: list[str] = field(default_factory=list)
    active: bool = True

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def deactivate(self) -> None:
        self.active = False
""",
    },
    {
        "id": "py_parameterized_sql",
        "language": "python",
        "notes": "Parameterized query — no SQL injection",
        "code": """\
from __future__ import annotations
import sqlite3
from typing import Optional


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> Optional[dict]:
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "email": row[2]}


def list_active_users(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name FROM users WHERE active = 1 ORDER BY name LIMIT ?",
        (min(limit, 1000),),
    )
    return [{"id": r[0], "name": r[1]} for r in cursor.fetchall()]
""",
    },
    {
        "id": "py_env_secrets",
        "language": "python",
        "notes": "Secrets from environment variables only",
        "code": """\
from __future__ import annotations
import os
import hmac
import hashlib


def get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    return url


def get_api_key(service: str) -> str:
    key = os.environ.get(f"{service.upper()}_API_KEY")
    if not key:
        raise RuntimeError(f"Missing API key for {service}")
    return key


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
""",
    },
    {
        "id": "py_subprocess_safe",
        "language": "python",
        "notes": "subprocess with list args (no shell=True)",
        "code": """\
from __future__ import annotations
import subprocess
import shlex
from pathlib import Path


def run_linter(file_path: Path) -> subprocess.CompletedProcess:
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    return subprocess.run(
        ["ruff", "check", str(file_path), "--output-format=json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def git_log_short(repo_dir: Path, n: int = 10) -> str:
    result = subprocess.run(
        ["git", "log", f"--oneline", f"-{n}"],
        capture_output=True,
        text=True,
        cwd=str(repo_dir),
        check=True,
        timeout=10,
    )
    return result.stdout
""",
    },
    {
        "id": "py_context_manager",
        "language": "python",
        "notes": "Context manager, explicit exception types",
        "code": """\
from __future__ import annotations
import json
from pathlib import Path
from typing import Any


def load_config(config_path: Path) -> dict[str, Any]:
    try:
        with config_path.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {config_path}: {exc}") from exc


def save_config(config_path: Path, data: dict[str, Any]) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
""",
    },
    {
        "id": "py_pydantic_model",
        "language": "python",
        "notes": "Pydantic v2 model with validators",
        "code": """\
from __future__ import annotations
import re
from pydantic import BaseModel, Field, field_validator


EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$")


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    email: str
    full_name: str = Field(max_length=200)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        reserved = {"admin", "root", "system", "null", "undefined"}
        if v.lower() in reserved:
            raise ValueError(f"Username '{v}' is reserved")
        return v
""",
    },
    {
        "id": "py_async_http",
        "language": "python",
        "notes": "Async HTTP client with timeout, no hardcoded URLs in secrets",
        "code": """\
from __future__ import annotations
import os
import asyncio
import httpx
from typing import Any


BASE_URL = os.environ.get("API_BASE_URL", "https://api.example.com")


async def fetch_json(client: httpx.AsyncClient, path: str) -> Any:
    response = await client.get(path, timeout=10.0)
    response.raise_for_status()
    return response.json()


async def post_json(client: httpx.AsyncClient, path: str, payload: dict) -> Any:
    response = await client.post(path, json=payload, timeout=30.0)
    response.raise_for_status()
    return response.json()


async def get_paginated(client: httpx.AsyncClient, path: str, page_size: int = 50) -> list[Any]:
    results: list[Any] = []
    page = 1
    while True:
        data = await fetch_json(client, f"{path}?page={page}&size={page_size}")
        items = data.get("items", [])
        results.extend(items)
        if not data.get("has_next"):
            break
        page += 1
    return results
""",
    },
    {
        "id": "py_type_annotations",
        "language": "python",
        "notes": "Fully typed utility functions",
        "code": """\
from __future__ import annotations
from typing import TypeVar, Callable, Iterable

T = TypeVar("T")
K = TypeVar("K")


def chunk(items: list[T], size: int) -> list[list[T]]:
    if size <= 0:
        raise ValueError("Chunk size must be positive")
    return [items[i : i + size] for i in range(0, len(items), size)]


def group_by(items: Iterable[T], key_fn: Callable[[T], K]) -> dict[K, list[T]]:
    groups: dict[K, list[T]] = {}
    for item in items:
        k = key_fn(item)
        groups.setdefault(k, []).append(item)
    return groups


def flatten(nested: list[list[T]]) -> list[T]:
    return [item for sublist in nested for item in sublist]


def dedupe_stable(items: list[T]) -> list[T]:
    seen: set = set()
    result: list[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
""",
    },
    {
        "id": "py_pathlib_clean",
        "language": "python",
        "notes": "Pathlib usage, safe path construction",
        "code": """\
from __future__ import annotations
from pathlib import Path
import shutil


ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java"}


def is_safe_path(base_dir: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def collect_source_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix in ALLOWED_EXTENSIONS
        and ".git" not in p.parts
        and "node_modules" not in p.parts
    )


def safe_copy(src: Path, dst_dir: Path, base: Path) -> None:
    if not is_safe_path(base, src):
        raise PermissionError(f"Path traversal attempt: {src}")
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst_dir / src.name)
""",
    },
    {
        "id": "py_logging_clean",
        "language": "python",
        "notes": "Structured logging, no sensitive data logged",
        "code": """\
from __future__ import annotations
import logging
import time
from functools import wraps
from typing import Callable, Any

logger = logging.getLogger(__name__)


def log_duration(name: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
                elapsed = (time.perf_counter() - start) * 1000
                logger.debug("%s completed in %.1fms", name, elapsed)
                return result
            except Exception:
                elapsed = (time.perf_counter() - start) * 1000
                logger.exception("%s failed after %.1fms", name, elapsed)
                raise
        return wrapper
    return decorator
""",
    },
    {
        "id": "py_enum_clean",
        "language": "python",
        "notes": "Clean enum usage",
        "code": """\
from __future__ import annotations
from enum import StrEnum, auto


class ReviewStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGED = "merged"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


BLOCKING_STATUSES = {ReviewStatus.REJECTED}
TERMINAL_STATUSES = {ReviewStatus.APPROVED, ReviewStatus.REJECTED, ReviewStatus.MERGED}


def can_transition(current: ReviewStatus, next_status: ReviewStatus) -> bool:
    transitions: dict[ReviewStatus, set[ReviewStatus]] = {
        ReviewStatus.PENDING: {ReviewStatus.IN_PROGRESS},
        ReviewStatus.IN_PROGRESS: {ReviewStatus.APPROVED, ReviewStatus.REJECTED},
        ReviewStatus.APPROVED: {ReviewStatus.MERGED},
        ReviewStatus.REJECTED: {ReviewStatus.PENDING},
        ReviewStatus.MERGED: set(),
    }
    return next_status in transitions.get(current, set())
""",
    },
    {
        "id": "py_fastapi_clean",
        "language": "python",
        "notes": "FastAPI endpoint with proper auth header, no raw SQL",
        "code": """\
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

router = APIRouter(prefix="/items", tags=["items"])


class ItemCreate(BaseModel):
    name: str
    description: str | None = None
    price: float


class ItemResponse(BaseModel):
    id: int
    name: str
    description: str | None
    price: float


async def get_current_user_id(authorization: str = "") -> int:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    token = authorization[7:]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    # Real implementation would validate JWT here
    return 1


@router.post("/", response_model=ItemResponse, status_code=status.HTTP_201_CREATED)
async def create_item(
    body: ItemCreate,
    user_id: int = Depends(get_current_user_id),
) -> ItemResponse:
    # Service layer call would go here
    return ItemResponse(id=1, name=body.name, description=body.description, price=body.price)
""",
    },
    {
        "id": "py_hashing_clean",
        "language": "python",
        "notes": "Password hashing with bcrypt, not md5/sha1",
        "code": """\
from __future__ import annotations
import hashlib
import hmac
import os
import secrets


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return key.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    salt = bytes.fromhex(stored_salt)
    key, _ = hash_password(password, salt)
    return hmac.compare_digest(key, stored_hash)


def derive_key(master_secret: str, context: str) -> bytes:
    return hashlib.blake2b(
        context.encode(),
        key=master_secret.encode()[:64],
        digest_size=32,
    ).digest()
""",
    },
    {
        "id": "py_generator_clean",
        "language": "python",
        "notes": "Generator-based streaming, low complexity",
        "code": """\
from __future__ import annotations
from typing import Generator, Iterator
from pathlib import Path
import json


def stream_jsonl(path: Path) -> Generator[dict, None, None]:
    with path.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_num}: {exc}") from exc


def take(n: int, it: Iterator) -> list:
    result = []
    for _ in range(n):
        try:
            result.append(next(it))
        except StopIteration:
            break
    return result
""",
    },
    {
        "id": "py_abc_clean",
        "language": "python",
        "notes": "Abstract base class, clean OOP",
        "code": """\
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable


@runtime_checkable
class Serializable(Protocol):
    def to_dict(self) -> dict: ...

    @classmethod
    def from_dict(cls, data: dict) -> "Serializable": ...


class BaseRepository(ABC):
    @abstractmethod
    async def get(self, id: int) -> dict | None: ...

    @abstractmethod
    async def list(self, limit: int = 50, offset: int = 0) -> list[dict]: ...

    @abstractmethod
    async def create(self, data: dict) -> dict: ...

    @abstractmethod
    async def delete(self, id: int) -> bool: ...


class InMemoryRepository(BaseRepository):
    def __init__(self) -> None:
        self._store: dict[int, dict] = {}
        self._next_id = 1

    async def get(self, id: int) -> dict | None:
        return self._store.get(id)

    async def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        items = sorted(self._store.values(), key=lambda x: x["id"])
        return items[offset : offset + limit]

    async def create(self, data: dict) -> dict:
        record = {**data, "id": self._next_id}
        self._store[self._next_id] = record
        self._next_id += 1
        return record

    async def delete(self, id: int) -> bool:
        return self._store.pop(id, None) is not None
""",
    },
    {
        "id": "py_cli_clean",
        "language": "python",
        "notes": "Clean CLI with argparse, typed",
        "code": """\
from __future__ import annotations
import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mytool",
        description="A well-designed CLI tool",
    )
    p.add_argument("input", type=Path, help="Input file path")
    p.add_argument("-o", "--output", type=Path, default=None, help="Output path")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--format", choices=["json", "text", "csv"], default="text")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        return 1
    output_path = args.output or args.input.with_suffix(".out")
    if args.verbose:
        print(f"Processing {args.input} → {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
""",
    },
    {
        "id": "py_testing_clean",
        "language": "python",
        "notes": "Clean pytest test file",
        "code": """\
from __future__ import annotations
import pytest


def add(a: int, b: int) -> int:
    return a + b


def divide(a: float, b: float) -> float:
    if b == 0:
        raise ZeroDivisionError("Cannot divide by zero")
    return a / b


class TestAdd:
    def test_positive(self) -> None:
        assert add(2, 3) == 5

    def test_negative(self) -> None:
        assert add(-1, 1) == 0

    def test_zero(self) -> None:
        assert add(0, 0) == 0


class TestDivide:
    def test_normal(self) -> None:
        assert divide(10.0, 4.0) == pytest.approx(2.5)

    def test_zero_denominator(self) -> None:
        with pytest.raises(ZeroDivisionError):
            divide(5.0, 0.0)
""",
    },
    {
        "id": "py_retry_clean",
        "language": "python",
        "notes": "Retry decorator with exponential backoff",
        "code": """\
from __future__ import annotations
import time
import logging
from typing import Callable, TypeVar, Any

logger = logging.getLogger(__name__)
T = TypeVar("T")


def retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable:
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts:
                        delay = backoff_base ** (attempt - 1)
                        logger.warning("Attempt %d/%d failed: %s. Retrying in %.1fs",
                                       attempt, max_attempts, exc, delay)
                        time.sleep(delay)
            raise RuntimeError(f"All {max_attempts} attempts failed") from last_exc
        return wrapper
    return decorator
""",
    },
    {
        "id": "py_cache_clean",
        "language": "python",
        "notes": "LRU cache wrapper, no secrets",
        "code": """\
from __future__ import annotations
import time
from functools import lru_cache
from threading import Lock


class TTLCache:
    def __init__(self, maxsize: int = 256, ttl_seconds: float = 300.0) -> None:
        self._store: dict[str, tuple[object, float]] = {}
        self._lock = Lock()
        self._maxsize = maxsize
        self._ttl = ttl_seconds

    def get(self, key: str) -> object | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: object) -> None:
        with self._lock:
            if len(self._store) >= self._maxsize:
                oldest = min(self._store.items(), key=lambda kv: kv[1][1])
                del self._store[oldest[0]]
            self._store[key] = (value, time.monotonic() + self._ttl)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)
""",
    },
    {
        "id": "py_config_clean",
        "language": "python",
        "notes": "Configuration from env, typed, no hardcoded values",
        "code": """\
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    database_url: str
    redis_url: str
    debug: bool
    max_connections: int
    request_timeout_seconds: float

    @classmethod
    def from_env(cls) -> "AppConfig":
        db = os.environ.get("DATABASE_URL", "")
        if not db:
            raise EnvironmentError("DATABASE_URL is required")
        return cls(
            database_url=db,
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            debug=os.environ.get("DEBUG", "0").lower() in ("1", "true", "yes"),
            max_connections=int(os.environ.get("MAX_CONNECTIONS", "10")),
            request_timeout_seconds=float(os.environ.get("REQUEST_TIMEOUT", "30")),
        )
""",
    },
    # ─────────────────────── JAVASCRIPT (15 samples) ────────────────────────
    {
        "id": "js_fetch_clean",
        "language": "javascript",
        "notes": "Fetch with proper error handling, no innerHTML",
        "code": """\
async function fetchUser(userId) {
  const response = await fetch(`/api/users/${encodeURIComponent(String(userId))}`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

function renderUserName(container, name) {
  container.textContent = name;  // safe — no innerHTML
}

async function loadAndRender(userId, container) {
  try {
    const user = await fetchUser(userId);
    renderUserName(container, user.name);
  } catch (err) {
    console.error('Failed to load user:', err);
    container.textContent = 'Error loading user';
  }
}
""",
    },
    {
        "id": "js_class_clean",
        "language": "javascript",
        "notes": "ES6 class, no var, proper encapsulation",
        "code": """\
class EventEmitter {
  #listeners = new Map();

  on(event, handler) {
    if (typeof handler !== 'function') {
      throw new TypeError('Handler must be a function');
    }
    const handlers = this.#listeners.get(event) ?? [];
    this.#listeners.set(event, [...handlers, handler]);
    return this;
  }

  off(event, handler) {
    const handlers = this.#listeners.get(event) ?? [];
    this.#listeners.set(event, handlers.filter(h => h !== handler));
    return this;
  }

  emit(event, ...args) {
    const handlers = this.#listeners.get(event) ?? [];
    for (const handler of handlers) {
      try {
        handler(...args);
      } catch (err) {
        console.error(`Error in ${event} handler:`, err);
      }
    }
  }
}
""",
    },
    {
        "id": "js_module_clean",
        "language": "javascript",
        "notes": "ES module, named exports, no console.log",
        "code": """\
/**
 * Utility functions for array manipulation.
 * @module array-utils
 */

export function chunk(array, size) {
  if (!Array.isArray(array)) throw new TypeError('Expected an array');
  if (size <= 0) throw new RangeError('Chunk size must be positive');
  const result = [];
  for (let i = 0; i < array.length; i += size) {
    result.push(array.slice(i, i + size));
  }
  return result;
}

export function groupBy(array, keyFn) {
  return array.reduce((acc, item) => {
    const key = keyFn(item);
    (acc[key] ??= []).push(item);
    return acc;
  }, {});
}

export function unique(array) {
  return [...new Set(array)];
}
""",
    },
    {
        "id": "js_promise_clean",
        "language": "javascript",
        "notes": "Promise chain with proper error handling",
        "code": """\
async function withRetry(fn, { maxAttempts = 3, delayMs = 1000 } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, delayMs * 2 ** (attempt - 1)));
      }
    }
  }
  throw lastError;
}

async function parallelLimit(tasks, concurrency) {
  const results = [];
  const executing = new Set();

  for (const task of tasks) {
    const p = Promise.resolve().then(() => task()).then(r => {
      executing.delete(p);
      return r;
    });
    results.push(p);
    executing.add(p);
    if (executing.size >= concurrency) {
      await Promise.race(executing);
    }
  }
  return Promise.all(results);
}
""",
    },
    {
        "id": "js_validation_clean",
        "language": "javascript",
        "notes": "Input validation, no eval, no innerHTML",
        "code": """\
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$/;
const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,50}$/;

function validateEmail(email) {
  if (typeof email !== 'string') return { valid: false, error: 'Must be a string' };
  if (!EMAIL_REGEX.test(email)) return { valid: false, error: 'Invalid email format' };
  return { valid: true };
}

function validateUsername(username) {
  if (typeof username !== 'string') return { valid: false, error: 'Must be a string' };
  if (!USERNAME_REGEX.test(username)) {
    return { valid: false, error: 'Username must be 3-50 alphanumeric characters' };
  }
  const reserved = new Set(['admin', 'root', 'system', 'null']);
  if (reserved.has(username.toLowerCase())) {
    return { valid: false, error: 'Username is reserved' };
  }
  return { valid: true };
}

function sanitizeForAttribute(value) {
  return String(value).replace(/["&<>]/g, c => ({
    '"': '&quot;', '&': '&amp;', '<': '&lt;', '>': '&gt;',
  }[c]));
}
""",
    },
    {
        "id": "js_observer_clean",
        "language": "javascript",
        "notes": "Observer pattern, no var, no console.log",
        "code": """\
class Store {
  #state;
  #subscribers = new Set();

  constructor(initialState) {
    this.#state = Object.freeze({ ...initialState });
  }

  getState() {
    return this.#state;
  }

  subscribe(listener) {
    if (typeof listener !== 'function') throw new TypeError('Listener must be a function');
    this.#subscribers.add(listener);
    return () => this.#subscribers.delete(listener);
  }

  dispatch(updater) {
    const nextState = Object.freeze({ ...this.#state, ...updater(this.#state) });
    this.#state = nextState;
    for (const sub of this.#subscribers) {
      sub(nextState);
    }
  }
}
""",
    },
    {
        "id": "js_dom_safe",
        "language": "javascript",
        "notes": "DOM manipulation via createElement, not innerHTML",
        "code": """\
function createCard(title, description) {
  const card = document.createElement('div');
  card.className = 'card';

  const h2 = document.createElement('h2');
  h2.textContent = title;   // safe

  const p = document.createElement('p');
  p.textContent = description;  // safe

  card.append(h2, p);
  return card;
}

function renderList(container, items, renderItem) {
  const fragment = document.createDocumentFragment();
  for (const item of items) {
    fragment.appendChild(renderItem(item));
  }
  container.replaceChildren(fragment);
}

function setAriaLabel(el, label) {
  el.setAttribute('aria-label', label);  // attribute, not html
}
""",
    },
    {
        "id": "js_localstorage_safe",
        "language": "javascript",
        "notes": "LocalStorage with JSON parse, no sensitive data",
        "code": """\
const PREFERENCES_KEY = 'app:preferences';

function savePreferences(prefs) {
  try {
    const serialized = JSON.stringify(prefs);
    localStorage.setItem(PREFERENCES_KEY, serialized);
  } catch {
    // Quota exceeded or private browsing — fail gracefully
  }
}

function loadPreferences() {
  try {
    const raw = localStorage.getItem(PREFERENCES_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function clearPreferences() {
  localStorage.removeItem(PREFERENCES_KEY);
}
""",
    },
    {
        "id": "js_iterator_clean",
        "language": "javascript",
        "notes": "Custom iterator, generator, no security issues",
        "code": """\
function* range(start, end, step = 1) {
  if (step <= 0) throw new RangeError('Step must be positive');
  for (let i = start; i < end; i += step) {
    yield i;
  }
}

function* take(n, iterable) {
  let count = 0;
  for (const item of iterable) {
    if (count >= n) return;
    yield item;
    count++;
  }
}

function* map(fn, iterable) {
  for (const item of iterable) {
    yield fn(item);
  }
}

function* filter(predicate, iterable) {
  for (const item of iterable) {
    if (predicate(item)) yield item;
  }
}

function collect(iterable) {
  return Array.from(iterable);
}
""",
    },
    {
        "id": "js_error_handling_clean",
        "language": "javascript",
        "notes": "Custom error classes, structured error handling",
        "code": """\
class AppError extends Error {
  constructor(message, code, statusCode = 500) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

class NotFoundError extends AppError {
  constructor(resource, id) {
    super(`${resource} with id ${id} not found`, 'NOT_FOUND', 404);
    this.resource = resource;
    this.id = id;
  }
}

class ValidationError extends AppError {
  constructor(field, reason) {
    super(`Validation failed for ${field}: ${reason}`, 'VALIDATION_ERROR', 400);
    this.field = field;
    this.reason = reason;
  }
}

function handleError(err, req, res) {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.code, message: err.message });
  } else {
    res.status(500).json({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' });
  }
}
""",
    },
    {
        "id": "js_debounce_throttle",
        "language": "javascript",
        "notes": "Debounce and throttle utilities, no security issues",
        "code": """\
function debounce(fn, delayMs) {
  let timer;
  return function debounced(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delayMs);
  };
}

function throttle(fn, intervalMs) {
  let lastCall = 0;
  let timer;
  return function throttled(...args) {
    const now = Date.now();
    const remaining = intervalMs - (now - lastCall);
    if (remaining <= 0) {
      lastCall = now;
      return fn.apply(this, args);
    }
    clearTimeout(timer);
    timer = setTimeout(() => {
      lastCall = Date.now();
      fn.apply(this, args);
    }, remaining);
  };
}
""",
    },
    {
        "id": "js_formdata_safe",
        "language": "javascript",
        "notes": "Form data handling without DOM XSS",
        "code": """\
async function submitForm(formEl) {
  const formData = new FormData(formEl);
  const body = Object.fromEntries(formData.entries());

  const response = await fetch('/api/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(err.message ?? 'Unknown error');
  }

  return response.json();
}

function displaySuccess(el, message) {
  el.textContent = message;  // safe — not innerHTML
  el.setAttribute('role', 'alert');
}
""",
    },
    {
        "id": "js_url_params_safe",
        "language": "javascript",
        "notes": "URL parsing with URLSearchParams, not string concat",
        "code": """\
function buildApiUrl(base, endpoint, params = {}) {
  const url = new URL(endpoint, base);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

function parseQueryParams() {
  const params = new URLSearchParams(window.location.search);
  return Object.fromEntries(params.entries());
}

function updateQueryParam(key, value) {
  const url = new URL(window.location.href);
  if (value === null || value === undefined) {
    url.searchParams.delete(key);
  } else {
    url.searchParams.set(key, String(value));
  }
  window.history.replaceState(null, '', url.toString());
}
""",
    },
    {
        "id": "js_immutable_clean",
        "language": "javascript",
        "notes": "Immutable update patterns — spread operator, no bracket mutation",
        "code": """\
function update(obj, path, value) {
  const keys = path.split('.');
  if (keys.length === 1) {
    return { ...obj, [keys[0]]: value };
  }
  const [head, ...tail] = keys;
  return {
    ...obj,
    [head]: update(obj[head] ?? {}, tail.join('.'), value),
  };
}

function removeKey(obj, key) {
  const { [key]: _, ...rest } = obj;
  return rest;
}

function safeMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    // Guard against prototype pollution — Object.hasOwn ensures own property only
    if (!Object.hasOwn(source, key)) continue;
    if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = safeMerge(result[key] ?? {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}
""",
    },
    {
        "id": "js_date_clean",
        "language": "javascript",
        "notes": "Date handling without eval",
        "code": """\
function formatDate(date, locale = 'en-US') {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(date);
}

function addDays(date, days) {
  const result = new Date(date.getTime());
  result.setDate(result.getDate() + days);
  return result;
}

function startOfDay(date) {
  const d = new Date(date.getTime());
  d.setHours(0, 0, 0, 0);
  return d;
}

function daysBetween(a, b) {
  const msPerDay = 1000 * 60 * 60 * 24;
  return Math.round(Math.abs(b.getTime() - a.getTime()) / msPerDay);
}
""",
    },
    # ─────────────────────── TYPESCRIPT (10 samples) ────────────────────────
    {
        "id": "ts_types_clean",
        "language": "typescript",
        "notes": "No any types, strict generics",
        "code": """\
type Result<T, E extends Error = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

function err<E extends Error>(error: E): Result<never, E> {
  return { ok: false, error };
}

function mapResult<T, U, E extends Error>(
  result: Result<T, E>,
  fn: (value: T) => U,
): Result<U, E> {
  if (result.ok) return ok(fn(result.value));
  return result;
}

async function tryCatch<T>(fn: () => Promise<T>): Promise<Result<T, Error>> {
  try {
    return ok(await fn());
  } catch (e) {
    return err(e instanceof Error ? e : new Error(String(e)));
  }
}
""",
    },
    {
        "id": "ts_interface_clean",
        "language": "typescript",
        "notes": "Interface-driven design, no any",
        "code": """\
interface Repository<T, ID> {
  findById(id: ID): Promise<T | null>;
  findAll(options?: { limit?: number; offset?: number }): Promise<T[]>;
  save(entity: Omit<T, 'id'>): Promise<T>;
  update(id: ID, partial: Partial<Omit<T, 'id'>>): Promise<T | null>;
  delete(id: ID): Promise<boolean>;
}

interface User {
  id: number;
  email: string;
  name: string;
  createdAt: Date;
}

class InMemoryUserRepository implements Repository<User, number> {
  private store = new Map<number, User>();
  private nextId = 1;

  async findById(id: number): Promise<User | null> {
    return this.store.get(id) ?? null;
  }

  async findAll({ limit = 50, offset = 0 } = {}): Promise<User[]> {
    return [...this.store.values()].slice(offset, offset + limit);
  }

  async save(data: Omit<User, 'id'>): Promise<User> {
    const user: User = { id: this.nextId++, ...data };
    this.store.set(user.id, user);
    return user;
  }

  async update(id: number, partial: Partial<Omit<User, 'id'>>): Promise<User | null> {
    const user = this.store.get(id);
    if (!user) return null;
    const updated: User = { ...user, ...partial };
    this.store.set(id, updated);
    return updated;
  }

  async delete(id: number): Promise<boolean> {
    return this.store.delete(id);
  }
}
""",
    },
    {
        "id": "ts_discriminated_union",
        "language": "typescript",
        "notes": "Discriminated unions, exhaustive checks",
        "code": """\
type Shape =
  | { kind: 'circle'; radius: number }
  | { kind: 'rectangle'; width: number; height: number }
  | { kind: 'triangle'; base: number; height: number };

function area(shape: Shape): number {
  switch (shape.kind) {
    case 'circle':
      return Math.PI * shape.radius ** 2;
    case 'rectangle':
      return shape.width * shape.height;
    case 'triangle':
      return 0.5 * shape.base * shape.height;
    default: {
      const _exhaustive: never = shape;
      throw new Error(`Unknown shape: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

function perimeter(shape: Shape): number {
  switch (shape.kind) {
    case 'circle':
      return 2 * Math.PI * shape.radius;
    case 'rectangle':
      return 2 * (shape.width + shape.height);
    case 'triangle':
      return shape.base + 2 * Math.sqrt((shape.height ** 2) + ((shape.base / 2) ** 2));
    default: {
      const _exhaustive: never = shape;
      throw new Error(`Unknown shape: ${JSON.stringify(_exhaustive)}`);
    }
  }
}
""",
    },
    {
        "id": "ts_generic_clean",
        "language": "typescript",
        "notes": "Generic utilities, no any",
        "code": """\
function groupBy<T, K extends string | number | symbol>(
  items: readonly T[],
  keyFn: (item: T) => K,
): Record<K, T[]> {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    if (!acc[key]) acc[key] = [];
    acc[key].push(item);
    return acc;
  }, {} as Record<K, T[]>);
}

function chunk<T>(array: readonly T[], size: number): T[][] {
  if (size <= 0) throw new RangeError('Chunk size must be positive');
  const result: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    result.push(array.slice(i, i + size) as T[]);
  }
  return result;
}

function keyBy<T, K extends string | number | symbol>(
  items: readonly T[],
  keyFn: (item: T) => K,
): Record<K, T> {
  return items.reduce((acc, item) => {
    acc[keyFn(item)] = item;
    return acc;
  }, {} as Record<K, T>);
}
""",
    },
    {
        "id": "ts_enum_clean",
        "language": "typescript",
        "notes": "Const enum, no any, proper typing",
        "code": """\
const enum HttpStatus {
  OK = 200,
  Created = 201,
  BadRequest = 400,
  Unauthorized = 401,
  Forbidden = 403,
  NotFound = 404,
  InternalServerError = 500,
}

interface ApiResponse<T> {
  status: HttpStatus;
  data?: T;
  error?: { code: string; message: string };
}

function success<T>(data: T): ApiResponse<T> {
  return { status: HttpStatus.OK, data };
}

function notFound(resource: string): ApiResponse<never> {
  return {
    status: HttpStatus.NotFound,
    error: { code: 'NOT_FOUND', message: `${resource} not found` },
  };
}

function badRequest(message: string): ApiResponse<never> {
  return {
    status: HttpStatus.BadRequest,
    error: { code: 'BAD_REQUEST', message },
  };
}
""",
    },
    {
        "id": "ts_react_component_clean",
        "language": "typescript",
        "notes": "React component, no dangerouslySetInnerHTML, no any",
        "code": """\
import React, { useState, useCallback } from 'react';

interface ButtonProps {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'secondary' | 'danger';
}

const Button: React.FC<ButtonProps> = ({
  label,
  onClick,
  disabled = false,
  variant = 'primary',
}) => {
  const [loading, setLoading] = useState(false);

  const handleClick = useCallback(async () => {
    if (disabled || loading) return;
    setLoading(true);
    try {
      await onClick();
    } finally {
      setLoading(false);
    }
  }, [disabled, loading, onClick]);

  return (
    <button
      onClick={handleClick}
      disabled={disabled || loading}
      className={`btn btn-${variant}`}
      aria-busy={loading}
    >
      {loading ? 'Loading…' : label}
    </button>
  );
};

export default Button;
""",
    },
    {
        "id": "ts_zod_validation",
        "language": "typescript",
        "notes": "Zod schema validation, no any",
        "code": """\
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number().int().positive(),
  email: z.string().email().max(254),
  name: z.string().min(1).max(200).trim(),
  role: z.enum(['admin', 'editor', 'viewer']),
  createdAt: z.coerce.date(),
});

type User = z.infer<typeof UserSchema>;

const CreateUserSchema = UserSchema.omit({ id: true, createdAt: true });
type CreateUserInput = z.infer<typeof CreateUserSchema>;

function parseUser(raw: unknown): User {
  return UserSchema.parse(raw);
}

function safeParseUser(raw: unknown): { success: true; data: User } | { success: false; errors: string[] } {
  const result = UserSchema.safeParse(raw);
  if (result.success) return { success: true, data: result.data };
  return {
    success: false,
    errors: result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
  };
}
""",
    },
    {
        "id": "ts_hooks_clean",
        "language": "typescript",
        "notes": "React hooks, no any, no dangerouslySetInnerHTML",
        "code": """\
import { useState, useEffect, useRef, useCallback } from 'react';

function useLocalStorage<T>(key: string, defaultValue: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? (JSON.parse(stored) as T) : defaultValue;
    } catch {
      return defaultValue;
    }
  });

  const set = useCallback((newValue: T) => {
    setValue(newValue);
    try {
      localStorage.setItem(key, JSON.stringify(newValue));
    } catch {
      // Quota or private-browsing — ignore
    }
  }, [key]);

  return [value, set];
}

function useDebounce<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(id);
  }, [value, delayMs]);
  return debounced;
}
""",
    },
    {
        "id": "ts_async_clean",
        "language": "typescript",
        "notes": "Async/await with typed errors, no any",
        "code": """\
interface FetchOptions {
  timeout?: number;
  retries?: number;
}

async function fetchWithTimeout<T>(url: string, options: FetchOptions = {}): Promise<T> {
  const { timeout = 10_000, retries = 0 } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json() as T;
  } catch (err) {
    clearTimeout(timer);
    if (retries > 0) {
      await new Promise(res => setTimeout(res, 1_000));
      return fetchWithTimeout<T>(url, { ...options, retries: retries - 1 });
    }
    throw err;
  }
}
""",
    },
    {
        "id": "ts_mapper_clean",
        "language": "typescript",
        "notes": "Type-safe mapper pattern",
        "code": """\
type Mapper<From, To> = (input: From) => To;

function compose<A, B, C>(f: Mapper<A, B>, g: Mapper<B, C>): Mapper<A, C> {
  return (a: A) => g(f(a));
}

function mapArray<T, U>(arr: readonly T[], fn: Mapper<T, U>): U[] {
  return arr.map(fn);
}

function filterMap<T, U>(arr: readonly T[], fn: (item: T) => U | null | undefined): U[] {
  const result: U[] = [];
  for (const item of arr) {
    const mapped = fn(item);
    if (mapped !== null && mapped !== undefined) {
      result.push(mapped);
    }
  }
  return result;
}

function pipe<T>(value: T, ...fns: Array<Mapper<T, T>>): T {
  return fns.reduce((acc, fn) => fn(acc), value);
}
""",
    },
    # ─────────────────────── GO (8 samples) ─────────────────────────────────
    {
        "id": "go_error_handling",
        "language": "go",
        "notes": "Explicit error handling, no panic in normal flow",
        "code": """\
package user

import (
    "context"
    "errors"
    "fmt"
)

var ErrNotFound = errors.New("user not found")
var ErrInvalidInput = errors.New("invalid input")

type User struct {
    ID    int64
    Name  string
    Email string
}

type Repository interface {
    FindByID(ctx context.Context, id int64) (*User, error)
    Create(ctx context.Context, u *User) (*User, error)
}

func GetUser(ctx context.Context, repo Repository, id int64) (*User, error) {
    if id <= 0 {
        return nil, fmt.Errorf("get user: %w: id must be positive, got %d", ErrInvalidInput, id)
    }
    user, err := repo.FindByID(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("get user %d: %w", id, err)
    }
    return user, nil
}
""",
    },
    {
        "id": "go_goroutine_safe",
        "language": "go",
        "notes": "Goroutine with WaitGroup, channel-based results",
        "code": """\
package processor

import (
    "context"
    "sync"
)

type Result struct {
    ID    int
    Value string
    Err   error
}

func ProcessAll(ctx context.Context, ids []int, process func(context.Context, int) (string, error)) []Result {
    results := make([]Result, len(ids))
    var wg sync.WaitGroup

    for i, id := range ids {
        wg.Add(1)
        go func(idx, id int) {
            defer wg.Done()
            val, err := process(ctx, id)
            results[idx] = Result{ID: id, Value: val, Err: err}
        }(i, id)
    }

    wg.Wait()
    return results
}
""",
    },
    {
        "id": "go_sql_parameterized",
        "language": "go",
        "notes": "Parameterized SQL query in Go",
        "code": """\
package store

import (
    "context"
    "database/sql"
)

type UserStore struct {
    db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
    return &UserStore{db: db}
}

func (s *UserStore) FindByEmail(ctx context.Context, email string) (*User, error) {
    row := s.db.QueryRowContext(
        ctx,
        "SELECT id, name, email FROM users WHERE email = $1 AND active = true",
        email,
    )
    var u User
    if err := row.Scan(&u.ID, &u.Name, &u.Email); err == sql.ErrNoRows {
        return nil, nil
    } else if err != nil {
        return nil, err
    }
    return &u, nil
}

func (s *UserStore) Create(ctx context.Context, name, email string) (*User, error) {
    var u User
    err := s.db.QueryRowContext(
        ctx,
        "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id, name, email",
        name, email,
    ).Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}

type User struct {
    ID    int64
    Name  string
    Email string
}
""",
    },
    {
        "id": "go_http_handler_clean",
        "language": "go",
        "notes": "HTTP handler with proper validation, no sql injection",
        "code": """\
package api

import (
    "encoding/json"
    "net/http"
    "strconv"
)

type createItemRequest struct {
    Name  string  `json:"name"`
    Price float64 `json:"price"`
}

func (h *Handler) CreateItem(w http.ResponseWriter, r *http.Request) {
    var req createItemRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request body", http.StatusBadRequest)
        return
    }
    if req.Name == "" {
        http.Error(w, "name is required", http.StatusBadRequest)
        return
    }
    if req.Price < 0 {
        http.Error(w, "price must be non-negative", http.StatusBadRequest)
        return
    }
    item, err := h.service.CreateItem(r.Context(), req.Name, req.Price)
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(item)
}
""",
    },
    {
        "id": "go_struct_methods",
        "language": "go",
        "notes": "Struct with methods, no globals, clean design",
        "code": """\
package cache

import (
    "sync"
    "time"
)

type entry struct {
    value     interface{}
    expiresAt time.Time
}

type Cache struct {
    mu      sync.RWMutex
    items   map[string]entry
    ttl     time.Duration
}

func New(ttl time.Duration) *Cache {
    return &Cache{items: make(map[string]entry), ttl: ttl}
}

func (c *Cache) Set(key string, value interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = entry{value: value, expiresAt: time.Now().Add(c.ttl)}
}

func (c *Cache) Get(key string) (interface{}, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    e, ok := c.items[key]
    if !ok || time.Now().After(e.expiresAt) {
        return nil, false
    }
    return e.value, true
}

func (c *Cache) Delete(key string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.items, key)
}
""",
    },
    {
        "id": "go_interface_clean",
        "language": "go",
        "notes": "Interface with multiple implementations",
        "code": """\
package notify

import (
    "context"
    "fmt"
)

type Notification struct {
    To      string
    Subject string
    Body    string
}

type Sender interface {
    Send(ctx context.Context, n Notification) error
}

type LogSender struct{}

func (s *LogSender) Send(_ context.Context, n Notification) error {
    fmt.Printf("[notify] to=%s subject=%s\\n", n.To, n.Subject)
    return nil
}

type MultiSender struct {
    senders []Sender
}

func NewMultiSender(senders ...Sender) *MultiSender {
    return &MultiSender{senders: senders}
}

func (m *MultiSender) Send(ctx context.Context, n Notification) error {
    var errs []error
    for _, s := range m.senders {
        if err := s.Send(ctx, n); err != nil {
            errs = append(errs, err)
        }
    }
    if len(errs) > 0 {
        return fmt.Errorf("send errors: %v", errs)
    }
    return nil
}
""",
    },
    {
        "id": "go_functional_clean",
        "language": "go",
        "notes": "Functional patterns in Go 1.21+",
        "code": """\
package fp

func Map[T, U any](slice []T, fn func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = fn(v)
    }
    return result
}

func Filter[T any](slice []T, pred func(T) bool) []T {
    var result []T
    for _, v := range slice {
        if pred(v) {
            result = append(result, v)
        }
    }
    return result
}

func Reduce[T, U any](slice []T, initial U, fn func(U, T) U) U {
    acc := initial
    for _, v := range slice {
        acc = fn(acc, v)
    }
    return acc
}

func GroupBy[T any, K comparable](slice []T, keyFn func(T) K) map[K][]T {
    result := make(map[K][]T)
    for _, v := range slice {
        k := keyFn(v)
        result[k] = append(result[k], v)
    }
    return result
}
""",
    },
    {
        "id": "go_config_clean",
        "language": "go",
        "notes": "Config from environment, no hardcoded secrets",
        "code": """\
package config

import (
    "fmt"
    "os"
    "strconv"
    "time"
)

type Config struct {
    DatabaseURL string
    RedisURL    string
    Port        int
    Debug       bool
    Timeout     time.Duration
}

func Load() (*Config, error) {
    dbURL := os.Getenv("DATABASE_URL")
    if dbURL == "" {
        return nil, fmt.Errorf("DATABASE_URL is required")
    }

    port := 8080
    if p := os.Getenv("PORT"); p != "" {
        var err error
        port, err = strconv.Atoi(p)
        if err != nil || port <= 0 || port > 65535 {
            return nil, fmt.Errorf("invalid PORT: %s", p)
        }
    }

    timeout := 30 * time.Second
    if t := os.Getenv("REQUEST_TIMEOUT_SECONDS"); t != "" {
        secs, err := strconv.ParseFloat(t, 64)
        if err != nil || secs <= 0 {
            return nil, fmt.Errorf("invalid REQUEST_TIMEOUT_SECONDS: %s", t)
        }
        timeout = time.Duration(secs * float64(time.Second))
    }

    return &Config{
        DatabaseURL: dbURL,
        RedisURL:    os.Getenv("REDIS_URL"),
        Port:        port,
        Debug:       os.Getenv("DEBUG") == "true",
        Timeout:     timeout,
    }, nil
}
""",
    },
    # ─────────────────────── RUST (4 samples) ───────────────────────────────
    {
        "id": "rust_result_clean",
        "language": "rust",
        "notes": "Result-based error handling, no unwrap in production paths",
        "code": """\
use std::fmt;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum AppError {
    Parse(ParseIntError),
    Validation(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Parse(e) => write!(f, "parse error: {}", e),
            AppError::Validation(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

impl From<ParseIntError> for AppError {
    fn from(e: ParseIntError) -> Self {
        AppError::Parse(e)
    }
}

pub fn parse_positive(s: &str) -> Result<u64, AppError> {
    let n: i64 = s.trim().parse()?;
    if n <= 0 {
        return Err(AppError::Validation(format!("expected positive, got {}", n)));
    }
    Ok(n as u64)
}
""",
    },
    {
        "id": "rust_struct_clean",
        "language": "rust",
        "notes": "Rust struct with builder pattern, no unsafe",
        "code": """\
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub timeout_ms: u64,
}

#[derive(Default)]
pub struct ConfigBuilder {
    host: Option<String>,
    port: Option<u16>,
    max_connections: Option<usize>,
    timeout_ms: Option<u64>,
}

impl ConfigBuilder {
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = Some(n);
        self
    }

    pub fn build(self) -> Result<Config, String> {
        Ok(Config {
            host: self.host.ok_or("host is required")?,
            port: self.port.unwrap_or(8080),
            max_connections: self.max_connections.unwrap_or(10),
            timeout_ms: self.timeout_ms.unwrap_or(30_000),
        })
    }
}
""",
    },
    {
        "id": "rust_iter_clean",
        "language": "rust",
        "notes": "Iterator combinators, no unsafe, no unwrap",
        "code": """\
pub fn word_count(text: &str) -> std::collections::HashMap<&str, usize> {
    text.split_whitespace()
        .fold(std::collections::HashMap::new(), |mut acc, word| {
            *acc.entry(word).or_insert(0) += 1;
            acc
        })
}

pub fn top_n<T: Ord>(items: impl Iterator<Item = T>, n: usize) -> Vec<T> {
    let mut heap: std::collections::BinaryHeap<T> = items.collect();
    (0..n).filter_map(|_| heap.pop()).collect()
}

pub fn chunk_iter<T>(v: Vec<T>, size: usize) -> Vec<Vec<T>> {
    if size == 0 { return vec![]; }
    v.chunks(size).map(|c| c.to_vec()).collect()
}
""",
    },
    {
        "id": "rust_traits_clean",
        "language": "rust",
        "notes": "Trait-based abstraction, no unsafe",
        "code": """\
use std::fmt;

pub trait Summary: fmt::Display {
    fn summarize(&self) -> String;
    fn word_count(&self) -> usize {
        self.summarize().split_whitespace().count()
    }
}

pub struct Article {
    pub title: String,
    pub content: String,
    pub author: String,
}

impl fmt::Display for Article {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} by {}", self.title, self.author)
    }
}

impl Summary for Article {
    fn summarize(&self) -> String {
        let words: Vec<&str> = self.content.split_whitespace().take(20).collect();
        format!("{}...", words.join(" "))
    }
}

pub fn notify(item: &impl Summary) {
    println!("Breaking news! {}", item.summarize());
}
""",
    },
    # ─────────────────────── JAVA (3 samples) ───────────────────────────────
    {
        "id": "java_builder_clean",
        "language": "java",
        "notes": "Builder pattern, no raw types, no resource leaks",
        "code": """\
package com.example.model;

import java.util.Objects;

public final class User {
    private final long id;
    private final String name;
    private final String email;
    private final boolean active;

    private User(Builder b) {
        this.id = b.id;
        this.name = Objects.requireNonNull(b.name, "name");
        this.email = Objects.requireNonNull(b.email, "email");
        this.active = b.active;
    }

    public long getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public boolean isActive() { return active; }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private long id;
        private String name;
        private String email;
        private boolean active = true;

        public Builder id(long id) { this.id = id; return this; }
        public Builder name(String name) { this.name = name; return this; }
        public Builder email(String email) { this.email = email; return this; }
        public Builder active(boolean active) { this.active = active; return this; }
        public User build() { return new User(this); }
    }
}
""",
    },
    {
        "id": "java_try_with_resources",
        "language": "java",
        "notes": "Try-with-resources, PreparedStatement, no broad catch",
        "code": """\
package com.example.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UserRepository {
    private static final String FIND_BY_ID =
        "SELECT id, name, email FROM users WHERE id = ? AND active = true";
    private static final String FIND_ALL =
        "SELECT id, name, email FROM users WHERE active = true ORDER BY id LIMIT ? OFFSET ?";

    private final Connection conn;

    public UserRepository(Connection conn) {
        this.conn = conn;
    }

    public Optional<User> findById(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
                return Optional.empty();
            }
        }
    }

    public List<User> findAll(int limit, int offset) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(FIND_ALL)) {
            ps.setInt(1, limit);
            ps.setInt(2, offset);
            try (ResultSet rs = ps.executeQuery()) {
                List<User> users = new ArrayList<>();
                while (rs.next()) {
                    users.add(mapRow(rs));
                }
                return users;
            }
        }
    }

    private User mapRow(ResultSet rs) throws SQLException {
        return User.builder()
            .id(rs.getLong("id"))
            .name(rs.getString("name"))
            .email(rs.getString("email"))
            .build();
    }
}

record User(long id, String name, String email) {}
""",
    },
    {
        "id": "java_stream_clean",
        "language": "java",
        "notes": "Java Streams, Optional chaining, no raw types",
        "code": """\
package com.example.util;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public final class StreamUtils {
    private StreamUtils() {}

    public static <T, K> Map<K, List<T>> groupBy(List<T> items, java.util.function.Function<T, K> keyFn) {
        return items.stream().collect(Collectors.groupingBy(keyFn));
    }

    public static <T extends Comparable<T>> Optional<T> max(List<T> items) {
        return items.stream().max(Comparator.naturalOrder());
    }

    public static <T extends Comparable<T>> Optional<T> min(List<T> items) {
        return items.stream().min(Comparator.naturalOrder());
    }

    public static <T> List<List<T>> partition(List<T> items, int size) {
        if (size <= 0) throw new IllegalArgumentException("Partition size must be positive");
        int total = items.size();
        return java.util.stream.IntStream.range(0, (total + size - 1) / size)
            .mapToObj(i -> items.subList(i * size, Math.min((i + 1) * size, total)))
            .collect(Collectors.toList());
    }
}
""",
    },
]
