"""Extended clean code corpus — 140 additional idiomatic snippets across 6 languages.

Supplements clean_corpus.py to bring the total clean corpus to 200+ samples.
Target: ~35 samples per language (Python, JavaScript, TypeScript, Go, Rust, Java).

Focus on patterns that commonly trigger false positives:
- Parameterized SQL queries
- subprocess with hardcoded commands
- File operations with validated paths
- Crypto usage (proper, not weak)
- Environment variable access for config
- Template rendering with escaped output
- Dynamic dispatch / reflection (legitimate use)
- API handlers, middleware, data processing
"""

from __future__ import annotations

EXTENDED_CLEAN_SAMPLES: list[dict] = [
    # ─────────────────────── PYTHON (15 samples) ─────────────────────────────
    {
        "id": "py_ext_sqlalchemy_param",
        "language": "python",
        "notes": "SQLAlchemy parameterized queries with bound parameters",
        "code": """\
from __future__ import annotations
from sqlalchemy import text
from sqlalchemy.orm import Session


def find_orders_by_status(session: Session, status: str, limit: int = 50) -> list[dict]:
    stmt = text(
        "SELECT id, customer_id, total FROM orders "
        "WHERE status = :status ORDER BY created_at DESC LIMIT :limit"
    )
    rows = session.execute(stmt, {"status": status, "limit": limit}).fetchall()
    return [{"id": r[0], "customer_id": r[1], "total": float(r[2])} for r in rows]


def update_order_status(session: Session, order_id: int, new_status: str) -> None:
    stmt = text("UPDATE orders SET status = :status WHERE id = :id")
    session.execute(stmt, {"status": new_status, "id": order_id})
    session.commit()
""",
    },
    {
        "id": "py_ext_subprocess_git",
        "language": "python",
        "notes": "subprocess with hardcoded git commands, no user input in args",
        "code": """\
from __future__ import annotations
import subprocess
from pathlib import Path


def get_changed_files(repo: Path, base_ref: str = "main") -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", base_ref, "HEAD"],
        capture_output=True,
        text=True,
        cwd=str(repo),
        check=True,
        timeout=30,
    )
    return [line for line in result.stdout.strip().splitlines() if line]


def get_commit_count(repo: Path) -> int:
    result = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        capture_output=True,
        text=True,
        cwd=str(repo),
        check=True,
        timeout=10,
    )
    return int(result.stdout.strip())
""",
    },
    {
        "id": "py_ext_crypto_proper",
        "language": "python",
        "notes": "Proper cryptographic usage with strong algorithms",
        "code": """\
from __future__ import annotations
import hashlib
import secrets
import hmac


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return salt, derived.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return hmac.compare_digest(derived.hex(), expected_hash)
""",
    },
    {
        "id": "py_ext_file_validated_path",
        "language": "python",
        "notes": "File operations with validated, constrained paths",
        "code": """\
from __future__ import annotations
from pathlib import Path

UPLOAD_DIR = Path("/var/app/uploads")


def safe_read_upload(filename: str) -> bytes:
    sanitized = Path(filename).name  # strip directory traversal
    target = UPLOAD_DIR / sanitized
    if not target.resolve().is_relative_to(UPLOAD_DIR.resolve()):
        raise ValueError("Invalid file path")
    return target.read_bytes()


def list_uploads() -> list[str]:
    return sorted(p.name for p in UPLOAD_DIR.iterdir() if p.is_file())
""",
    },
    {
        "id": "py_ext_env_config",
        "language": "python",
        "notes": "Environment variable config loading with defaults and validation",
        "code": """\
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    port: int
    debug: bool
    log_level: str
    max_connections: int

    @classmethod
    def from_env(cls) -> AppConfig:
        return cls(
            port=int(os.environ.get("PORT", "8080")),
            debug=os.environ.get("DEBUG", "false").lower() == "true",
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            max_connections=int(os.environ.get("MAX_CONNECTIONS", "100")),
        )
""",
    },
    {
        "id": "py_ext_middleware_auth",
        "language": "python",
        "notes": "Auth middleware with proper token validation",
        "code": """\
from __future__ import annotations
import time
from typing import Any, Callable
from functools import wraps


def require_auth(get_user: Callable[[str], dict | None]):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            token = request.headers.get("Authorization", "").removeprefix("Bearer ")
            if not token:
                return {"error": "Missing authorization"}, 401
            user = get_user(token)
            if user is None:
                return {"error": "Invalid token"}, 403
            request.user = user
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def rate_limit_key(request: Any) -> str:
    return f"rl:{request.remote_addr}:{int(time.time()) // 60}"
""",
    },
    {
        "id": "py_ext_data_pipeline",
        "language": "python",
        "notes": "Data processing pipeline with generators",
        "code": """\
from __future__ import annotations
import csv
import io
from typing import Iterator


def parse_csv_rows(content: str) -> Iterator[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        yield {k.strip(): v.strip() for k, v in row.items()}


def filter_valid_emails(rows: Iterator[dict[str, str]]) -> Iterator[dict[str, str]]:
    for row in rows:
        email = row.get("email", "")
        if "@" in email and "." in email.split("@")[-1]:
            yield row


def aggregate_by_field(rows: Iterator[dict[str, str]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = row.get(field, "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts
""",
    },
    {
        "id": "py_ext_jinja_escaped",
        "language": "python",
        "notes": "Jinja2 template rendering with autoescaping enabled",
        "code": """\
from __future__ import annotations
from jinja2 import Environment, PackageLoader, select_autoescape


def create_template_env() -> Environment:
    return Environment(
        loader=PackageLoader("myapp", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_user_page(env: Environment, username: str, bio: str) -> str:
    template = env.get_template("profile.html")
    return template.render(username=username, bio=bio)


def render_email(env: Environment, subject: str, body: str) -> str:
    template = env.get_template("email.html")
    return template.render(subject=subject, body=body)
""",
    },
    {
        "id": "py_ext_celery_task",
        "language": "python",
        "notes": "Celery task definition with proper retry and timeout",
        "code": """\
from __future__ import annotations
from celery import Celery

app = Celery("tasks", broker="redis://localhost:6379/0")


@app.task(bind=True, max_retries=3, soft_time_limit=120)
def process_report(self, report_id: int) -> dict:
    try:
        # simulate report generation
        data = {"report_id": report_id, "status": "complete", "rows": 42}
        return data
    except Exception as exc:
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)


@app.task(ignore_result=True)
def send_notification(user_id: int, message: str) -> None:
    # fire-and-forget notification
    pass
""",
    },
    {
        "id": "py_ext_pytest_fixtures",
        "language": "python",
        "notes": "pytest fixtures and parametrize, testing utilities",
        "code": """\
from __future__ import annotations
import pytest


@pytest.fixture
def sample_users() -> list[dict]:
    return [
        {"id": 1, "name": "Alice", "active": True},
        {"id": 2, "name": "Bob", "active": False},
        {"id": 3, "name": "Charlie", "active": True},
    ]


@pytest.mark.parametrize("input_val,expected", [
    ("hello", "HELLO"),
    ("world", "WORLD"),
    ("", ""),
])
def test_uppercase(input_val: str, expected: str) -> None:
    assert input_val.upper() == expected


def test_active_users(sample_users: list[dict]) -> None:
    active = [u for u in sample_users if u["active"]]
    assert len(active) == 2
    assert all(u["active"] for u in active)
""",
    },
    {
        "id": "py_ext_asyncio_queue",
        "language": "python",
        "notes": "asyncio queue-based worker pattern",
        "code": """\
from __future__ import annotations
import asyncio
import logging

logger = logging.getLogger(__name__)


async def worker(name: str, queue: asyncio.Queue[str]) -> None:
    while True:
        item = await queue.get()
        try:
            logger.info("Worker %s processing: %s", name, item)
            await asyncio.sleep(0.1)  # simulate work
        finally:
            queue.task_done()


async def run_pipeline(items: list[str], num_workers: int = 3) -> None:
    queue: asyncio.Queue[str] = asyncio.Queue()
    for item in items:
        await queue.put(item)

    workers = [asyncio.create_task(worker(f"w-{i}", queue)) for i in range(num_workers)]
    await queue.join()

    for w in workers:
        w.cancel()
""",
    },
    {
        "id": "py_ext_dynamic_dispatch",
        "language": "python",
        "notes": "Plugin registry with dynamic dispatch, no eval",
        "code": """\
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class Transformer(Protocol):
    def transform(self, data: str) -> str: ...


class UpperTransformer:
    def transform(self, data: str) -> str:
        return data.upper()


class StripTransformer:
    def transform(self, data: str) -> str:
        return data.strip()


_REGISTRY: dict[str, type[Transformer]] = {
    "upper": UpperTransformer,
    "strip": StripTransformer,
}


def apply_transform(name: str, data: str) -> str:
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown transformer: {name}")
    return cls().transform(data)
""",
    },
    {
        "id": "py_ext_redis_cache",
        "language": "python",
        "notes": "Redis caching with proper serialization",
        "code": """\
from __future__ import annotations
import json
from typing import Any


class CacheClient:
    def __init__(self, redis_client: Any, default_ttl: int = 3600) -> None:
        self._redis = redis_client
        self._ttl = default_ttl

    def get(self, key: str) -> Any | None:
        raw = self._redis.get(f"cache:{key}")
        if raw is None:
            return None
        return json.loads(raw)

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        serialized = json.dumps(value, default=str)
        self._redis.setex(f"cache:{key}", ttl or self._ttl, serialized)

    def delete(self, key: str) -> None:
        self._redis.delete(f"cache:{key}")

    def clear_prefix(self, prefix: str) -> int:
        keys = list(self._redis.scan_iter(f"cache:{prefix}:*"))
        if keys:
            return self._redis.delete(*keys)
        return 0
""",
    },
    {
        "id": "py_ext_webhook_verify",
        "language": "python",
        "notes": "Webhook signature verification with constant-time comparison",
        "code": """\
from __future__ import annotations
import hashlib
import hmac


def verify_github_webhook(payload: bytes, signature: str, secret: str) -> bool:
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)


def verify_stripe_webhook(payload: bytes, sig_header: str, secret: str) -> bool:
    parts = dict(item.split("=", 1) for item in sig_header.split(",") if "=" in item)
    timestamp = parts.get("t", "")
    v1_sig = parts.get("v1", "")
    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1_sig)
""",
    },
    {
        "id": "py_ext_json_schema",
        "language": "python",
        "notes": "JSON schema validation, no eval or exec",
        "code": """\
from __future__ import annotations
from typing import Any


SCHEMA = {
    "type": "object",
    "required": ["name", "age"],
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 100},
        "age": {"type": "integer", "minimum": 0, "maximum": 150},
        "email": {"type": "string", "format": "email"},
    },
}


def validate_payload(data: dict[str, Any], schema: dict) -> list[str]:
    errors: list[str] = []
    for field in schema.get("required", []):
        if field not in data:
            errors.append(f"Missing required field: {field}")
    for field, rules in schema.get("properties", {}).items():
        if field in data:
            value = data[field]
            if rules.get("type") == "string" and not isinstance(value, str):
                errors.append(f"{field}: expected string")
            if rules.get("type") == "integer" and not isinstance(value, int):
                errors.append(f"{field}: expected integer")
    return errors
""",
    },

    # ─────────────────────── JAVASCRIPT (15 samples) ─────────────────────────
    {
        "id": "js_ext_express_middleware",
        "language": "javascript",
        "notes": "Express middleware chain with proper error handling",
        "code": """\
const express = require('express');
const app = express();

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  next();
}

function validateContentType(req, res, next) {
  if (req.method === 'POST' && !req.is('application/json')) {
    return res.status(415).json({ error: 'Content-Type must be application/json' });
  }
  next();
}

app.use(requestLogger);
app.use(express.json({ limit: '1mb' }));
app.use(validateContentType);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});
""",
    },
    {
        "id": "js_ext_fetch_retry",
        "language": "javascript",
        "notes": "Fetch with retry logic and timeout, no eval",
        "code": """\
async function fetchWithRetry(url, options = {}, maxRetries = 3) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || 10000);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!response.ok && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
        continue;
      }
      return response;
    } catch (err) {
      clearTimeout(timeout);
      if (attempt === maxRetries) throw err;
      await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
    }
  }
}
""",
    },
    {
        "id": "js_ext_event_emitter",
        "language": "javascript",
        "notes": "Custom event emitter pattern, no dynamic code execution",
        "code": """\
class TypedEmitter {
  #listeners = new Map();

  on(event, handler) {
    if (!this.#listeners.has(event)) {
      this.#listeners.set(event, new Set());
    }
    this.#listeners.get(event).add(handler);
    return () => this.off(event, handler);
  }

  off(event, handler) {
    const handlers = this.#listeners.get(event);
    if (handlers) handlers.delete(handler);
  }

  emit(event, ...args) {
    const handlers = this.#listeners.get(event);
    if (!handlers) return;
    for (const handler of handlers) {
      handler(...args);
    }
  }

  once(event, handler) {
    const wrapper = (...args) => {
      this.off(event, wrapper);
      handler(...args);
    };
    return this.on(event, wrapper);
  }
}

module.exports = { TypedEmitter };
""",
    },
    {
        "id": "js_ext_dom_textcontent",
        "language": "javascript",
        "notes": "DOM manipulation via textContent, not innerHTML",
        "code": """\
function renderUserList(users, containerEl) {
  containerEl.replaceChildren();

  for (const user of users) {
    const li = document.createElement('li');
    li.textContent = user.name;
    li.dataset.userId = String(user.id);

    const badge = document.createElement('span');
    badge.textContent = user.role;
    badge.className = 'badge';
    li.appendChild(badge);

    containerEl.appendChild(li);
  }
}

function showError(messageEl, text) {
  messageEl.textContent = text;
  messageEl.classList.add('error');
  setTimeout(() => messageEl.classList.remove('error'), 3000);
}
""",
    },
    {
        "id": "js_ext_map_reduce",
        "language": "javascript",
        "notes": "Array processing with map/reduce/filter, pure functions",
        "code": """\
function groupBy(items, keyFn) {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    if (!acc[key]) acc[key] = [];
    acc[key].push(item);
    return acc;
  }, {});
}

function summarizeOrders(orders) {
  return orders
    .filter(o => o.status === 'completed')
    .map(o => ({ id: o.id, total: o.items.reduce((s, i) => s + i.price * i.qty, 0) }))
    .sort((a, b) => b.total - a.total);
}

function movingAverage(values, window) {
  return values.map((_, i, arr) => {
    const start = Math.max(0, i - window + 1);
    const slice = arr.slice(start, i + 1);
    return slice.reduce((a, b) => a + b, 0) / slice.length;
  });
}
""",
    },
    {
        "id": "js_ext_websocket_clean",
        "language": "javascript",
        "notes": "WebSocket handler with proper close/error handling",
        "code": """\
class WebSocketClient {
  #ws = null;
  #reconnectDelay = 1000;
  #maxDelay = 30000;

  constructor(url, onMessage) {
    this.url = url;
    this.onMessage = onMessage;
  }

  connect() {
    this.#ws = new WebSocket(this.url);

    this.#ws.onopen = () => {
      this.#reconnectDelay = 1000;
      console.log('WebSocket connected');
    };

    this.#ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.onMessage(data);
      } catch (err) {
        console.error('Invalid message format:', err.message);
      }
    };

    this.#ws.onclose = () => {
      setTimeout(() => this.connect(), this.#reconnectDelay);
      this.#reconnectDelay = Math.min(this.#reconnectDelay * 2, this.#maxDelay);
    };

    this.#ws.onerror = (err) => {
      console.error('WebSocket error:', err.message);
      this.#ws.close();
    };
  }

  send(data) {
    if (this.#ws?.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify(data));
    }
  }

  close() {
    this.#ws?.close();
  }
}
""",
    },
    {
        "id": "js_ext_crypto_subtle",
        "language": "javascript",
        "notes": "Web Crypto API for hashing, not deprecated crypto",
        "code": """\
async function hashData(data) {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

function generateNonce() {
  return crypto.getRandomValues(new Uint8Array(12));
}
""",
    },
    {
        "id": "js_ext_proxy_pattern",
        "language": "javascript",
        "notes": "Proxy pattern for validation, not eval-based metaprogramming",
        "code": """\
function createValidatedObject(schema) {
  const data = {};
  return new Proxy(data, {
    set(target, prop, value) {
      const validator = schema[prop];
      if (validator && !validator(value)) {
        throw new TypeError(`Invalid value for ${String(prop)}`);
      }
      target[prop] = value;
      return true;
    },
    get(target, prop) {
      return target[prop];
    },
  });
}

const userSchema = {
  name: (v) => typeof v === 'string' && v.length > 0,
  age: (v) => typeof v === 'number' && v >= 0 && v <= 150,
  email: (v) => typeof v === 'string' && v.includes('@'),
};

module.exports = { createValidatedObject, userSchema };
""",
    },
    {
        "id": "js_ext_pagination",
        "language": "javascript",
        "notes": "Cursor-based pagination helper, safe string handling",
        "code": """\
function encodeCursor(id, timestamp) {
  const payload = JSON.stringify({ id, ts: timestamp });
  return Buffer.from(payload).toString('base64url');
}

function decodeCursor(cursor) {
  try {
    const payload = Buffer.from(cursor, 'base64url').toString('utf-8');
    const parsed = JSON.parse(payload);
    if (typeof parsed.id !== 'number' || typeof parsed.ts !== 'number') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function paginateResults(items, cursor, pageSize = 20) {
  const decoded = cursor ? decodeCursor(cursor) : null;
  const start = decoded ? items.findIndex(i => i.id === decoded.id) + 1 : 0;
  const page = items.slice(start, start + pageSize);
  const nextCursor = page.length === pageSize
    ? encodeCursor(page[page.length - 1].id, page[page.length - 1].createdAt)
    : null;
  return { data: page, nextCursor };
}
""",
    },
    {
        "id": "js_ext_worker_pool",
        "language": "javascript",
        "notes": "Worker thread pool pattern with structured messaging",
        "code": """\
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

class WorkerPool {
  #workers = [];
  #queue = [];

  constructor(scriptPath, poolSize = 4) {
    for (let i = 0; i < poolSize; i++) {
      const worker = new Worker(scriptPath);
      worker.busy = false;
      worker.on('message', (result) => {
        worker.busy = false;
        worker.currentResolve(result);
        this.#processQueue();
      });
      this.#workers.push(worker);
    }
  }

  execute(data) {
    return new Promise((resolve, reject) => {
      this.#queue.push({ data, resolve, reject });
      this.#processQueue();
    });
  }

  #processQueue() {
    const idle = this.#workers.find(w => !w.busy);
    if (!idle || this.#queue.length === 0) return;
    const { data, resolve } = this.#queue.shift();
    idle.busy = true;
    idle.currentResolve = resolve;
    idle.postMessage(data);
  }

  async destroy() {
    await Promise.all(this.#workers.map(w => w.terminate()));
  }
}

module.exports = { WorkerPool };
""",
    },
    {
        "id": "js_ext_sanitize_input",
        "language": "javascript",
        "notes": "Input sanitization without relying on innerHTML",
        "code": """\
function sanitizeFilename(name) {
  return name
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/^[.-]+/, '')
    .slice(0, 255);
}

function normalizeWhitespace(text) {
  return text.replace(/\\s+/g, ' ').trim();
}

function parseIntSafe(value, defaultVal = 0) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : defaultVal;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

module.exports = { sanitizeFilename, normalizeWhitespace, parseIntSafe, clamp };
""",
    },
    {
        "id": "js_ext_stream_transform",
        "language": "javascript",
        "notes": "Node.js Transform stream for data processing",
        "code": """\
const { Transform } = require('stream');

class JsonLineTransform extends Transform {
  #buffer = '';

  constructor() {
    super({ readableObjectMode: true });
  }

  _transform(chunk, _encoding, callback) {
    this.#buffer += chunk.toString();
    const lines = this.#buffer.split('\\n');
    this.#buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        this.push(JSON.parse(trimmed));
      } catch (err) {
        this.emit('parse-error', { line: trimmed, error: err.message });
      }
    }
    callback();
  }

  _flush(callback) {
    if (this.#buffer.trim()) {
      try {
        this.push(JSON.parse(this.#buffer.trim()));
      } catch {
        // ignore trailing incomplete line
      }
    }
    callback();
  }
}

module.exports = { JsonLineTransform };
""",
    },
    {
        "id": "js_ext_config_loader",
        "language": "javascript",
        "notes": "Config loader from env vars, no secrets in source code",
        "code": """\
function loadConfig() {
  const required = ['NODE_ENV', 'PORT'];
  const missing = required.filter(key => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required env vars: ${missing.join(', ')}`);
  }

  return Object.freeze({
    env: process.env.NODE_ENV,
    port: Number.parseInt(process.env.PORT, 10),
    logLevel: process.env.LOG_LEVEL || 'info',
    corsOrigin: process.env.CORS_ORIGIN || '*',
    rateLimitWindow: Number.parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10),
    rateLimitMax: Number.parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  });
}

module.exports = { loadConfig };
""",
    },
    {
        "id": "js_ext_linked_list",
        "language": "javascript",
        "notes": "Data structure implementation, pure logic",
        "code": """\
class ListNode {
  constructor(value, next = null) {
    this.value = value;
    this.next = next;
  }
}

class LinkedList {
  #head = null;
  #size = 0;

  get size() { return this.#size; }

  push(value) {
    this.#head = new ListNode(value, this.#head);
    this.#size++;
  }

  pop() {
    if (!this.#head) return undefined;
    const value = this.#head.value;
    this.#head = this.#head.next;
    this.#size--;
    return value;
  }

  toArray() {
    const result = [];
    let current = this.#head;
    while (current) {
      result.push(current.value);
      current = current.next;
    }
    return result;
  }

  *[Symbol.iterator]() {
    let current = this.#head;
    while (current) {
      yield current.value;
      current = current.next;
    }
  }
}

module.exports = { LinkedList };
""",
    },
    {
        "id": "js_ext_csp_headers",
        "language": "javascript",
        "notes": "Content Security Policy headers setup, security best practice",
        "code": """\
function securityHeaders() {
  return (req, res, next) => {
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  };
}

module.exports = { securityHeaders };
""",
    },

    # ─────────────────────── TYPESCRIPT (15 samples) ──────────────────────────
    {
        "id": "ts_ext_api_handler",
        "language": "typescript",
        "notes": "Express-style API handler with typed request/response",
        "code": """\
import { Request, Response, NextFunction } from 'express';

interface PaginationQuery {
  page?: string;
  limit?: string;
}

interface ApiResponse<T> {
  data: T;
  meta: { page: number; limit: number; total: number };
}

async function listUsers(
  req: Request<{}, {}, {}, PaginationQuery>,
  res: Response<ApiResponse<{ id: number; name: string }[]>>,
  _next: NextFunction,
): Promise<void> {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const offset = (page - 1) * limit;

  // Assume db is a safe parameterized query layer
  const users = [{ id: 1, name: 'Alice' }];
  const total = 1;

  res.json({ data: users, meta: { page, limit, total } });
}

export { listUsers };
""",
    },
    {
        "id": "ts_ext_result_type",
        "language": "typescript",
        "notes": "Result type pattern for error handling without exceptions",
        "code": """\
type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

function parseJson<T>(raw: string): Result<T, string> {
  try {
    return ok(JSON.parse(raw) as T);
  } catch (e) {
    return err(`Invalid JSON: ${(e as Error).message}`);
  }
}

function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw result.error;
  return result.value;
}

export { Result, ok, err, parseJson, unwrap };
""",
    },
    {
        "id": "ts_ext_repository_pattern",
        "language": "typescript",
        "notes": "Repository pattern with generics, no raw SQL strings",
        "code": """\
interface Entity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}

interface Repository<T extends Entity> {
  findById(id: string): Promise<T | null>;
  findMany(filter: Partial<T>, limit?: number): Promise<T[]>;
  create(data: Omit<T, 'id' | 'createdAt' | 'updatedAt'>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T | null>;
  delete(id: string): Promise<boolean>;
}

class InMemoryRepository<T extends Entity> implements Repository<T> {
  private store = new Map<string, T>();

  async findById(id: string): Promise<T | null> {
    return this.store.get(id) ?? null;
  }

  async findMany(_filter: Partial<T>, limit = 100): Promise<T[]> {
    return Array.from(this.store.values()).slice(0, limit);
  }

  async create(data: Omit<T, 'id' | 'createdAt' | 'updatedAt'>): Promise<T> {
    const now = new Date();
    const entity = { ...data, id: crypto.randomUUID(), createdAt: now, updatedAt: now } as T;
    this.store.set(entity.id, entity);
    return entity;
  }

  async update(id: string, data: Partial<T>): Promise<T | null> {
    const existing = this.store.get(id);
    if (!existing) return null;
    const updated = { ...existing, ...data, updatedAt: new Date() };
    this.store.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<boolean> {
    return this.store.delete(id);
  }
}

export { Entity, Repository, InMemoryRepository };
""",
    },
    {
        "id": "ts_ext_middleware_chain",
        "language": "typescript",
        "notes": "Type-safe middleware chain pattern",
        "code": """\
type Context = {
  headers: Record<string, string>;
  body: unknown;
  state: Record<string, unknown>;
};

type Middleware = (ctx: Context, next: () => Promise<void>) => Promise<void>;

function compose(middlewares: Middleware[]): Middleware {
  return async (ctx, next) => {
    let index = -1;
    async function dispatch(i: number): Promise<void> {
      if (i <= index) throw new Error('next() called multiple times');
      index = i;
      const fn = i < middlewares.length ? middlewares[i] : next;
      await fn(ctx, () => dispatch(i + 1));
    }
    await dispatch(0);
  };
}

const logger: Middleware = async (ctx, next) => {
  const start = Date.now();
  await next();
  console.log(`Request processed in ${Date.now() - start}ms`);
};

const cors: Middleware = async (ctx, next) => {
  ctx.state['cors'] = true;
  await next();
};

export { Context, Middleware, compose, logger, cors };
""",
    },
    {
        "id": "ts_ext_state_machine",
        "language": "typescript",
        "notes": "Type-safe finite state machine, exhaustive transitions",
        "code": """\
type OrderState = 'pending' | 'confirmed' | 'shipped' | 'delivered' | 'cancelled';

type OrderEvent =
  | { type: 'CONFIRM' }
  | { type: 'SHIP'; trackingId: string }
  | { type: 'DELIVER' }
  | { type: 'CANCEL'; reason: string };

interface Order {
  id: string;
  state: OrderState;
  trackingId?: string;
  cancelReason?: string;
}

function transition(order: Order, event: OrderEvent): Order {
  switch (order.state) {
    case 'pending':
      if (event.type === 'CONFIRM') return { ...order, state: 'confirmed' };
      if (event.type === 'CANCEL') return { ...order, state: 'cancelled', cancelReason: event.reason };
      break;
    case 'confirmed':
      if (event.type === 'SHIP') return { ...order, state: 'shipped', trackingId: event.trackingId };
      if (event.type === 'CANCEL') return { ...order, state: 'cancelled', cancelReason: event.reason };
      break;
    case 'shipped':
      if (event.type === 'DELIVER') return { ...order, state: 'delivered' };
      break;
  }
  return order; // no valid transition
}

export { Order, OrderEvent, OrderState, transition };
""",
    },
    {
        "id": "ts_ext_di_container",
        "language": "typescript",
        "notes": "Simple DI container with type safety",
        "code": """\
type Factory<T> = () => T;

class Container {
  private factories = new Map<string, Factory<unknown>>();
  private singletons = new Map<string, unknown>();

  register<T>(key: string, factory: Factory<T>, singleton = false): void {
    if (singleton) {
      this.factories.set(key, () => {
        if (!this.singletons.has(key)) {
          this.singletons.set(key, factory());
        }
        return this.singletons.get(key)!;
      });
    } else {
      this.factories.set(key, factory);
    }
  }

  resolve<T>(key: string): T {
    const factory = this.factories.get(key);
    if (!factory) {
      throw new Error(`No registration for key: ${key}`);
    }
    return factory() as T;
  }

  has(key: string): boolean {
    return this.factories.has(key);
  }
}

export { Container };
""",
    },
    {
        "id": "ts_ext_rxjs_operators",
        "language": "typescript",
        "notes": "Custom observable operators, reactive patterns",
        "code": """\
import { Observable, OperatorFunction } from 'rxjs';
import { filter, map, scan, distinctUntilChanged } from 'rxjs/operators';

interface StockTick {
  symbol: string;
  price: number;
  timestamp: number;
}

function filterBySymbol(symbol: string): OperatorFunction<StockTick, StockTick> {
  return filter((tick: StockTick) => tick.symbol === symbol);
}

function toMovingAverage(windowSize: number): OperatorFunction<StockTick, number> {
  return (source: Observable<StockTick>) =>
    source.pipe(
      map((tick) => tick.price),
      scan((acc: number[], price) => [...acc.slice(-(windowSize - 1)), price], []),
      map((window) => window.reduce((a, b) => a + b, 0) / window.length),
      distinctUntilChanged(),
    );
}

export { StockTick, filterBySymbol, toMovingAverage };
""",
    },
    {
        "id": "ts_ext_prisma_queries",
        "language": "typescript",
        "notes": "Prisma ORM queries, parameterized by design",
        "code": """\
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function getUserWithPosts(userId: string) {
  return prisma.user.findUnique({
    where: { id: userId },
    include: {
      posts: {
        where: { published: true },
        orderBy: { createdAt: 'desc' },
        take: 10,
      },
    },
  });
}

async function searchPosts(query: string, page: number, pageSize: number) {
  const skip = (page - 1) * pageSize;
  const [posts, total] = await Promise.all([
    prisma.post.findMany({
      where: { title: { contains: query, mode: 'insensitive' } },
      skip,
      take: pageSize,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.post.count({
      where: { title: { contains: query, mode: 'insensitive' } },
    }),
  ]);
  return { posts, total, page, pageSize };
}

export { getUserWithPosts, searchPosts };
""",
    },
    {
        "id": "ts_ext_testing_utils",
        "language": "typescript",
        "notes": "Testing utilities with type-safe mocks",
        "code": """\
type Mock<T extends (...args: any[]) => any> = T & {
  calls: Parameters<T>[];
  reset(): void;
};

function createMock<T extends (...args: any[]) => any>(impl?: T): Mock<T> {
  const calls: Parameters<T>[] = [];
  const fn = ((...args: any[]) => {
    calls.push(args as Parameters<T>);
    return impl?.(...args);
  }) as Mock<T>;
  fn.calls = calls;
  fn.reset = () => { calls.length = 0; };
  return fn;
}

function createFakeTimer() {
  let now = 0;
  return {
    now: () => now,
    advance: (ms: number) => { now += ms; },
    reset: () => { now = 0; },
  };
}

export { Mock, createMock, createFakeTimer };
""",
    },
    {
        "id": "ts_ext_branded_types",
        "language": "typescript",
        "notes": "Branded types for type-safe IDs",
        "code": """\
declare const __brand: unique symbol;

type Brand<T, B extends string> = T & { [__brand]: B };

type UserId = Brand<string, 'UserId'>;
type OrderId = Brand<string, 'OrderId'>;
type ProductId = Brand<string, 'ProductId'>;

function createUserId(id: string): UserId {
  if (!id || id.length < 1) throw new Error('Invalid user ID');
  return id as UserId;
}

function createOrderId(id: string): OrderId {
  if (!id.startsWith('ord_')) throw new Error('Order ID must start with ord_');
  return id as OrderId;
}

function getOrderForUser(userId: UserId, orderId: OrderId): string {
  return `Fetching order ${orderId} for user ${userId}`;
}

export { UserId, OrderId, ProductId, createUserId, createOrderId, getOrderForUser };
""",
    },
    {
        "id": "ts_ext_async_iterator",
        "language": "typescript",
        "notes": "Async iterator for paginated API consumption",
        "code": """\
interface PageResponse<T> {
  items: T[];
  nextCursor: string | null;
}

async function* paginate<T>(
  fetcher: (cursor: string | null) => Promise<PageResponse<T>>,
): AsyncGenerator<T[], void, undefined> {
  let cursor: string | null = null;
  do {
    const page = await fetcher(cursor);
    yield page.items;
    cursor = page.nextCursor;
  } while (cursor !== null);
}

async function collectAll<T>(
  fetcher: (cursor: string | null) => Promise<PageResponse<T>>,
  maxPages = 100,
): Promise<T[]> {
  const results: T[] = [];
  let count = 0;
  for await (const batch of paginate(fetcher)) {
    results.push(...batch);
    if (++count >= maxPages) break;
  }
  return results;
}

export { PageResponse, paginate, collectAll };
""",
    },
    {
        "id": "ts_ext_env_validation",
        "language": "typescript",
        "notes": "Environment variable validation with Zod",
        "code": """\
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'staging', 'production']),
  PORT: z.coerce.number().int().min(1).max(65535),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url().optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  MAX_UPLOAD_SIZE_MB: z.coerce.number().positive().default(10),
});

type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const formatted = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\\n');
    throw new Error(`Invalid environment variables:\\n${formatted}`);
  }
  return result.data;
}

export { Env, envSchema, loadEnv };
""",
    },
    {
        "id": "ts_ext_rate_limiter",
        "language": "typescript",
        "notes": "Sliding window rate limiter implementation",
        "code": """\
interface RateLimitEntry {
  timestamps: number[];
}

class SlidingWindowRateLimiter {
  private store = new Map<string, RateLimitEntry>();
  private readonly windowMs: number;
  private readonly maxRequests: number;

  constructor(windowMs: number, maxRequests: number) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    let entry = this.store.get(key);

    if (!entry) {
      entry = { timestamps: [] };
      this.store.set(key, entry);
    }

    entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);

    if (entry.timestamps.length >= this.maxRequests) {
      return false;
    }

    entry.timestamps.push(now);
    return true;
  }

  remaining(key: string): number {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const entry = this.store.get(key);
    if (!entry) return this.maxRequests;
    const active = entry.timestamps.filter((ts) => ts > cutoff).length;
    return Math.max(0, this.maxRequests - active);
  }
}

export { SlidingWindowRateLimiter };
""",
    },
    {
        "id": "ts_ext_event_sourcing",
        "language": "typescript",
        "notes": "Event sourcing aggregate pattern",
        "code": """\
interface DomainEvent {
  type: string;
  timestamp: Date;
  aggregateId: string;
}

interface AccountCreated extends DomainEvent {
  type: 'AccountCreated';
  ownerName: string;
}

interface FundsDeposited extends DomainEvent {
  type: 'FundsDeposited';
  amount: number;
}

interface FundsWithdrawn extends DomainEvent {
  type: 'FundsWithdrawn';
  amount: number;
}

type AccountEvent = AccountCreated | FundsDeposited | FundsWithdrawn;

interface AccountState {
  id: string;
  ownerName: string;
  balance: number;
}

function applyEvent(state: AccountState | null, event: AccountEvent): AccountState {
  switch (event.type) {
    case 'AccountCreated':
      return { id: event.aggregateId, ownerName: event.ownerName, balance: 0 };
    case 'FundsDeposited':
      if (!state) throw new Error('Account not found');
      return { ...state, balance: state.balance + event.amount };
    case 'FundsWithdrawn':
      if (!state) throw new Error('Account not found');
      if (state.balance < event.amount) throw new Error('Insufficient funds');
      return { ...state, balance: state.balance - event.amount };
  }
}

function rehydrate(events: AccountEvent[]): AccountState {
  return events.reduce<AccountState | null>(
    (state, event) => applyEvent(state, event),
    null,
  ) as AccountState;
}

export { AccountEvent, AccountState, applyEvent, rehydrate };
""",
    },
    {
        "id": "ts_ext_circuit_breaker",
        "language": "typescript",
        "notes": "Circuit breaker pattern for external service calls",
        "code": """\
type CircuitState = 'closed' | 'open' | 'half-open';

interface CircuitBreakerOptions {
  failureThreshold: number;
  resetTimeoutMs: number;
}

class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failureCount = 0;
  private lastFailureTime = 0;
  private readonly options: CircuitBreakerOptions;

  constructor(options: CircuitBreakerOptions) {
    this.options = options;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime > this.options.resetTimeoutMs) {
        this.state = 'half-open';
      } else {
        throw new Error('Circuit breaker is open');
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.options.failureThreshold) {
      this.state = 'open';
    }
  }

  getState(): CircuitState {
    return this.state;
  }
}

export { CircuitBreaker, CircuitBreakerOptions };
""",
    },

    # ─────────────────────── GO (25 samples) ─────────────────────────────────
    {
        "id": "go_ext_http_middleware",
        "language": "go",
        "notes": "HTTP middleware with logging and recovery",
        "code": """\
package middleware

import (
\t"log"
\t"net/http"
\t"time"
)

func Logger(next http.Handler) http.Handler {
\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
\t\tstart := time.Now()
\t\tnext.ServeHTTP(w, r)
\t\tlog.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
\t})
}

func Recover(next http.Handler) http.Handler {
\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
\t\tdefer func() {
\t\t\tif err := recover(); err != nil {
\t\t\t\tlog.Printf("panic recovered: %v", err)
\t\t\t\thttp.Error(w, "Internal Server Error", http.StatusInternalServerError)
\t\t\t}
\t\t}()
\t\tnext.ServeHTTP(w, r)
\t})
}

func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
\tfor i := len(middlewares) - 1; i >= 0; i-- {
\t\th = middlewares[i](h)
\t}
\treturn h
}
""",
    },
    {
        "id": "go_ext_sql_prepared",
        "language": "go",
        "notes": "Prepared SQL statements with parameter binding",
        "code": """\
package store

import (
\t"context"
\t"database/sql"
\t"time"
)

type User struct {
\tID        int64
\tName      string
\tEmail     string
\tCreatedAt time.Time
}

type UserStore struct {
\tdb *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
\treturn &UserStore{db: db}
}

func (s *UserStore) GetByID(ctx context.Context, id int64) (*User, error) {
\trow := s.db.QueryRowContext(ctx,
\t\t"SELECT id, name, email, created_at FROM users WHERE id = $1", id)
\tvar u User
\tif err := row.Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt); err != nil {
\t\treturn nil, err
\t}
\treturn &u, nil
}

func (s *UserStore) Create(ctx context.Context, name, email string) (*User, error) {
\tvar u User
\terr := s.db.QueryRowContext(ctx,
\t\t"INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id, name, email, created_at",
\t\tname, email,
\t).Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt)
\tif err != nil {
\t\treturn nil, err
\t}
\treturn &u, nil
}
""",
    },
    {
        "id": "go_ext_context_cancel",
        "language": "go",
        "notes": "Context cancellation and timeout patterns",
        "code": """\
package worker

import (
\t"context"
\t"fmt"
\t"time"
)

func ProcessWithTimeout(ctx context.Context, item string, timeout time.Duration) error {
\tctx, cancel := context.WithTimeout(ctx, timeout)
\tdefer cancel()

\tresultCh := make(chan string, 1)
\terrCh := make(chan error, 1)

\tgo func() {
\t\t// simulate work
\t\ttime.Sleep(100 * time.Millisecond)
\t\tresultCh <- fmt.Sprintf("processed: %s", item)
\t}()

\tselect {
\tcase result := <-resultCh:
\t\tfmt.Println(result)
\t\treturn nil
\tcase err := <-errCh:
\t\treturn err
\tcase <-ctx.Done():
\t\treturn ctx.Err()
\t}
}
""",
    },
    {
        "id": "go_ext_json_handler",
        "language": "go",
        "notes": "JSON API handler with input validation",
        "code": """\
package api

import (
\t"encoding/json"
\t"net/http"
\t"strings"
)

type CreateItemRequest struct {
\tName        string `json:"name"`
\tDescription string `json:"description"`
}

type ErrorResponse struct {
\tError string `json:"error"`
}

func (r *CreateItemRequest) Validate() []string {
\tvar errs []string
\tif strings.TrimSpace(r.Name) == "" {
\t\terrs = append(errs, "name is required")
\t}
\tif len(r.Name) > 200 {
\t\terrs = append(errs, "name must be under 200 characters")
\t}
\treturn errs
}

func HandleCreateItem(w http.ResponseWriter, r *http.Request) {
\tif r.Method != http.MethodPost {
\t\thttp.Error(w, "method not allowed", http.StatusMethodNotAllowed)
\t\treturn
\t}

\tvar req CreateItemRequest
\tif err := json.NewDecoder(r.Body).Decode(&req); err != nil {
\t\tw.WriteHeader(http.StatusBadRequest)
\t\tjson.NewEncoder(w).Encode(ErrorResponse{Error: "invalid JSON"})
\t\treturn
\t}

\tif errs := req.Validate(); len(errs) > 0 {
\t\tw.WriteHeader(http.StatusUnprocessableEntity)
\t\tjson.NewEncoder(w).Encode(ErrorResponse{Error: strings.Join(errs, "; ")})
\t\treturn
\t}

\tw.WriteHeader(http.StatusCreated)
\tjson.NewEncoder(w).Encode(map[string]string{"status": "created", "name": req.Name})
}
""",
    },
    {
        "id": "go_ext_mutex_safe",
        "language": "go",
        "notes": "Mutex-protected concurrent map access",
        "code": """\
package cache

import (
\t"sync"
\t"time"
)

type entry struct {
\tvalue     interface{}
\texpiresAt time.Time
}

type TTLCache struct {
\tmu      sync.RWMutex
\titems   map[string]entry
\tdefTTL  time.Duration
}

func NewTTLCache(defaultTTL time.Duration) *TTLCache {
\treturn &TTLCache{
\t\titems:  make(map[string]entry),
\t\tdefTTL: defaultTTL,
\t}
}

func (c *TTLCache) Get(key string) (interface{}, bool) {
\tc.mu.RLock()
\te, ok := c.items[key]
\tc.mu.RUnlock()
\tif !ok || time.Now().After(e.expiresAt) {
\t\treturn nil, false
\t}
\treturn e.value, true
}

func (c *TTLCache) Set(key string, value interface{}) {
\tc.mu.Lock()
\tc.items[key] = entry{value: value, expiresAt: time.Now().Add(c.defTTL)}
\tc.mu.Unlock()
}

func (c *TTLCache) Delete(key string) {
\tc.mu.Lock()
\tdelete(c.items, key)
\tc.mu.Unlock()
}
""",
    },
    {
        "id": "go_ext_table_test",
        "language": "go",
        "notes": "Table-driven tests, idiomatic Go testing",
        "code": """\
package mathutil

import "testing"

func Add(a, b int) int { return a + b }

func TestAdd(t *testing.T) {
\ttests := []struct {
\t\tname     string
\t\ta, b     int
\t\texpected int
\t}{
\t\t{"positive", 2, 3, 5},
\t\t{"negative", -1, -2, -3},
\t\t{"mixed", -1, 5, 4},
\t\t{"zero", 0, 0, 0},
\t\t{"large", 1000000, 2000000, 3000000},
\t}

\tfor _, tt := range tests {
\t\tt.Run(tt.name, func(t *testing.T) {
\t\t\tgot := Add(tt.a, tt.b)
\t\t\tif got != tt.expected {
\t\t\t\tt.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.expected)
\t\t\t}
\t\t})
\t}
}
""",
    },
    {
        "id": "go_ext_channel_pipeline",
        "language": "go",
        "notes": "Channel-based pipeline with proper goroutine lifecycle",
        "code": """\
package pipeline

import "context"

func Generate(ctx context.Context, values ...int) <-chan int {
\tout := make(chan int)
\tgo func() {
\t\tdefer close(out)
\t\tfor _, v := range values {
\t\t\tselect {
\t\t\tcase out <- v:
\t\t\tcase <-ctx.Done():
\t\t\t\treturn
\t\t\t}
\t\t}
\t}()
\treturn out
}

func Double(ctx context.Context, in <-chan int) <-chan int {
\tout := make(chan int)
\tgo func() {
\t\tdefer close(out)
\t\tfor v := range in {
\t\t\tselect {
\t\t\tcase out <- v * 2:
\t\t\tcase <-ctx.Done():
\t\t\t\treturn
\t\t\t}
\t\t}
\t}()
\treturn out
}

func Filter(ctx context.Context, in <-chan int, predicate func(int) bool) <-chan int {
\tout := make(chan int)
\tgo func() {
\t\tdefer close(out)
\t\tfor v := range in {
\t\t\tif predicate(v) {
\t\t\t\tselect {
\t\t\t\tcase out <- v:
\t\t\t\tcase <-ctx.Done():
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t}
\t\t}
\t}()
\treturn out
}
""",
    },
    {
        "id": "go_ext_embed_static",
        "language": "go",
        "notes": "Embedding static files with go:embed",
        "code": """\
package server

import (
\t"embed"
\t"io/fs"
\t"net/http"
)

//go:embed static/*
var staticFiles embed.FS

func StaticHandler() http.Handler {
\tsub, err := fs.Sub(staticFiles, "static")
\tif err != nil {
\t\tpanic(err)
\t}
\treturn http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
""",
    },
    {
        "id": "go_ext_option_pattern",
        "language": "go",
        "notes": "Functional options pattern for configuration",
        "code": """\
package server

import (
\t"time"
)

type Server struct {
\taddr         string
\treadTimeout  time.Duration
\twriteTimeout time.Duration
\tmaxBodySize  int64
}

type Option func(*Server)

func WithAddr(addr string) Option {
\treturn func(s *Server) { s.addr = addr }
}

func WithReadTimeout(d time.Duration) Option {
\treturn func(s *Server) { s.readTimeout = d }
}

func WithWriteTimeout(d time.Duration) Option {
\treturn func(s *Server) { s.writeTimeout = d }
}

func WithMaxBodySize(size int64) Option {
\treturn func(s *Server) { s.maxBodySize = size }
}

func NewServer(opts ...Option) *Server {
\ts := &Server{
\t\taddr:         ":8080",
\t\treadTimeout:  15 * time.Second,
\t\twriteTimeout: 15 * time.Second,
\t\tmaxBodySize:  1 << 20, // 1MB
\t}
\tfor _, opt := range opts {
\t\topt(s)
\t}
\treturn s
}
""",
    },
    {
        "id": "go_ext_graceful_shutdown",
        "language": "go",
        "notes": "Graceful HTTP server shutdown with signal handling",
        "code": """\
package main

import (
\t"context"
\t"log"
\t"net/http"
\t"os"
\t"os/signal"
\t"syscall"
\t"time"
)

func run() error {
\tmux := http.NewServeMux()
\tmux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
\t\tw.Write([]byte("ok"))
\t})

\tsrv := &http.Server{
\t\tAddr:         ":8080",
\t\tHandler:      mux,
\t\tReadTimeout:  10 * time.Second,
\t\tWriteTimeout: 10 * time.Second,
\t}

\terrCh := make(chan error, 1)
\tgo func() {
\t\tlog.Printf("listening on %s", srv.Addr)
\t\terrCh <- srv.ListenAndServe()
\t}()

\tquit := make(chan os.Signal, 1)
\tsignal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

\tselect {
\tcase err := <-errCh:
\t\treturn err
\tcase sig := <-quit:
\t\tlog.Printf("received signal %v, shutting down", sig)
\t}

\tctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
\tdefer cancel()
\treturn srv.Shutdown(ctx)
}
""",
    },
    {
        "id": "go_ext_crypto_hash",
        "language": "go",
        "notes": "Proper cryptographic hashing with bcrypt",
        "code": """\
package auth

import (
\t"crypto/rand"
\t"crypto/subtle"
\t"encoding/hex"
\t"fmt"

\t"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
\thash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
\tif err != nil {
\t\treturn "", fmt.Errorf("hashing password: %w", err)
\t}
\treturn string(hash), nil
}

func CheckPassword(hash, password string) bool {
\terr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
\treturn err == nil
}

func GenerateToken(nbytes int) (string, error) {
\tb := make([]byte, nbytes)
\tif _, err := rand.Read(b); err != nil {
\t\treturn "", err
\t}
\treturn hex.EncodeToString(b), nil
}

func ConstantTimeCompare(a, b string) bool {
\treturn subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
""",
    },
    {
        "id": "go_ext_env_config",
        "language": "go",
        "notes": "Environment-based config loading with defaults",
        "code": """\
package config

import (
\t"fmt"
\t"os"
\t"strconv"
)

type Config struct {
\tPort        int
\tDatabaseURL string
\tLogLevel    string
\tDebug       bool
}

func Load() (*Config, error) {
\tdbURL := os.Getenv("DATABASE_URL")
\tif dbURL == "" {
\t\treturn nil, fmt.Errorf("DATABASE_URL is required")
\t}

\tport := 8080
\tif p := os.Getenv("PORT"); p != "" {
\t\tvar err error
\t\tport, err = strconv.Atoi(p)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("invalid PORT: %w", err)
\t\t}
\t}

\treturn &Config{
\t\tPort:        port,
\t\tDatabaseURL: dbURL,
\t\tLogLevel:    getEnvOrDefault("LOG_LEVEL", "info"),
\t\tDebug:       os.Getenv("DEBUG") == "true",
\t}, nil
}

func getEnvOrDefault(key, defaultVal string) string {
\tif v := os.Getenv(key); v != "" {
\t\treturn v
\t}
\treturn defaultVal
}
""",
    },
    {
        "id": "go_ext_retry_backoff",
        "language": "go",
        "notes": "Retry with exponential backoff and jitter",
        "code": """\
package retry

import (
\t"context"
\t"math"
\t"math/rand"
\t"time"
)

type Config struct {
\tMaxAttempts int
\tBaseDelay   time.Duration
\tMaxDelay    time.Duration
}

func DefaultConfig() Config {
\treturn Config{
\t\tMaxAttempts: 5,
\t\tBaseDelay:   100 * time.Millisecond,
\t\tMaxDelay:    30 * time.Second,
\t}
}

func Do(ctx context.Context, cfg Config, fn func() error) error {
\tvar lastErr error
\tfor attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
\t\tif err := fn(); err == nil {
\t\t\treturn nil
\t\t} else {
\t\t\tlastErr = err
\t\t}

\t\tif attempt < cfg.MaxAttempts-1 {
\t\t\tdelay := time.Duration(float64(cfg.BaseDelay) * math.Pow(2, float64(attempt)))
\t\t\tif delay > cfg.MaxDelay {
\t\t\t\tdelay = cfg.MaxDelay
\t\t\t}
\t\t\tjitter := time.Duration(rand.Int63n(int64(delay / 2)))
\t\t\tselect {
\t\t\tcase <-time.After(delay + jitter):
\t\t\tcase <-ctx.Done():
\t\t\t\treturn ctx.Err()
\t\t\t}
\t\t}
\t}
\treturn lastErr
}
""",
    },
    {
        "id": "go_ext_interface_mock",
        "language": "go",
        "notes": "Interface-based mocking pattern for testing",
        "code": """\
package email

import "context"

type Sender interface {
\tSend(ctx context.Context, to, subject, body string) error
}

type SMTPSender struct {
\tHost string
\tPort int
}

func (s *SMTPSender) Send(_ context.Context, to, subject, body string) error {
\t// real SMTP implementation would go here
\t_ = to
\t_ = subject
\t_ = body
\treturn nil
}

// MockSender is used in tests
type MockSender struct {
\tCalls []SendCall
\tErr   error
}

type SendCall struct {
\tTo, Subject, Body string
}

func (m *MockSender) Send(_ context.Context, to, subject, body string) error {
\tm.Calls = append(m.Calls, SendCall{To: to, Subject: subject, Body: body})
\treturn m.Err
}
""",
    },
    {
        "id": "go_ext_worker_pool",
        "language": "go",
        "notes": "Worker pool pattern with bounded concurrency",
        "code": """\
package pool

import (
\t"context"
\t"sync"
)

type Task func(ctx context.Context) error

type Result struct {
\tIndex int
\tErr   error
}

func Run(ctx context.Context, tasks []Task, maxWorkers int) []Result {
\tresults := make([]Result, len(tasks))
\tvar mu sync.Mutex
\tsem := make(chan struct{}, maxWorkers)
\tvar wg sync.WaitGroup

\tfor i, task := range tasks {
\t\twg.Add(1)
\t\tgo func(idx int, t Task) {
\t\t\tdefer wg.Done()
\t\t\tsem <- struct{}{}
\t\t\tdefer func() { <-sem }()

\t\t\terr := t(ctx)
\t\t\tmu.Lock()
\t\t\tresults[idx] = Result{Index: idx, Err: err}
\t\t\tmu.Unlock()
\t\t}(i, task)
\t}

\twg.Wait()
\treturn results
}
""",
    },
    {
        "id": "go_ext_validator",
        "language": "go",
        "notes": "Input validation helpers, no reflection-based eval",
        "code": """\
package validate

import (
\t"fmt"
\t"regexp"
\t"strings"
)

var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$`)

type ValidationError struct {
\tField   string
\tMessage string
}

func (e ValidationError) Error() string {
\treturn fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func Required(field, value string) *ValidationError {
\tif strings.TrimSpace(value) == "" {
\t\treturn &ValidationError{Field: field, Message: "is required"}
\t}
\treturn nil
}

func MaxLength(field, value string, max int) *ValidationError {
\tif len(value) > max {
\t\treturn &ValidationError{Field: field, Message: fmt.Sprintf("must be at most %d characters", max)}
\t}
\treturn nil
}

func Email(field, value string) *ValidationError {
\tif !emailRe.MatchString(value) {
\t\treturn &ValidationError{Field: field, Message: "must be a valid email"}
\t}
\treturn nil
}

func Collect(checks ...*ValidationError) []ValidationError {
\tvar errs []ValidationError
\tfor _, e := range checks {
\t\tif e != nil {
\t\t\terrs = append(errs, *e)
\t\t}
\t}
\treturn errs
}
""",
    },
    {
        "id": "go_ext_template_html",
        "language": "go",
        "notes": "html/template with autoescaping (not text/template)",
        "code": """\
package render

import (
\t"bytes"
\t"html/template"
)

var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<head><title>{{.Name}}'s Profile</title></head>
<body>
  <h1>{{.Name}}</h1>
  <p>{{.Bio}}</p>
  <p>Member since: {{.JoinDate}}</p>
</body>
</html>
`))

type ProfileData struct {
\tName     string
\tBio      string
\tJoinDate string
}

func RenderProfile(data ProfileData) (string, error) {
\tvar buf bytes.Buffer
\tif err := profileTmpl.Execute(&buf, data); err != nil {
\t\treturn "", err
\t}
\treturn buf.String(), nil
}
""",
    },

    # ─────────────────────── RUST (25 samples) ────────────────────────────────
    {
        "id": "rust_ext_error_handling",
        "language": "rust",
        "notes": "Custom error types with thiserror",
        "code": """\
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("unauthorized")]
    Unauthorized,
}

pub type Result<T> = std::result::Result<T, AppError>;

pub fn find_user(id: u64) -> Result<String> {
    if id == 0 {
        return Err(AppError::Validation("id must be positive".into()));
    }
    Ok(format!("user_{}", id))
}
""",
    },
    {
        "id": "rust_ext_builder",
        "language": "rust",
        "notes": "Builder pattern with type-safe construction",
        "code": """\
#[derive(Debug)]
pub struct HttpRequest {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    timeout_ms: u64,
}

pub struct RequestBuilder {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    timeout_ms: u64,
}

impl RequestBuilder {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: None,
            timeout_ms: 30_000,
        }
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn build(self) -> HttpRequest {
        HttpRequest {
            url: self.url,
            method: self.method,
            headers: self.headers,
            body: self.body,
            timeout_ms: self.timeout_ms,
        }
    }
}
""",
    },
    {
        "id": "rust_ext_serde_models",
        "language": "rust",
        "notes": "Serde serialization with validation",
        "code": """\
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

impl CreateUserRequest {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.name.trim().is_empty() {
            errors.push("name is required".into());
        }
        if !self.email.contains('@') {
            errors.push("invalid email format".into());
        }
        if self.roles.len() > 10 {
            errors.push("too many roles".into());
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
    pub meta: ResponseMeta,
}

#[derive(Debug, Serialize)]
pub struct ResponseMeta {
    pub request_id: String,
    pub duration_ms: u64,
}
""",
    },
    {
        "id": "rust_ext_option_combinators",
        "language": "rust",
        "notes": "Option/Result combinators, no unwrap in production paths",
        "code": """\
use std::collections::HashMap;

pub struct Config {
    values: HashMap<String, String>,
}

impl Config {
    pub fn new(values: HashMap<String, String>) -> Self {
        Self { values }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.values
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.values.get(key).and_then(|v| v.parse().ok())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.values.get(key).and_then(|v| match v.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        })
    }

    pub fn require(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .ok_or_else(|| format!("missing required config key: {}", key))
    }
}
""",
    },
    {
        "id": "rust_ext_async_handler",
        "language": "rust",
        "notes": "Axum async handler with extractors",
        "code": """\
use axum::{extract::Path, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct UserResponse {
    pub id: u64,
    pub name: String,
    pub email: String,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}

pub async fn get_user(
    Path(user_id): Path<u64>,
) -> Result<Json<UserResponse>, StatusCode> {
    if user_id == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    // In production, this would query a database
    Ok(Json(UserResponse {
        id: user_id,
        name: "Alice".into(),
        email: "alice@example.com".into(),
    }))
}

pub async fn update_user(
    Path(user_id): Path<u64>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    if user_id == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(UserResponse {
        id: user_id,
        name: payload.name.unwrap_or_else(|| "Alice".into()),
        email: payload.email.unwrap_or_else(|| "alice@example.com".into()),
    }))
}
""",
    },
    {
        "id": "rust_ext_iterator_chain",
        "language": "rust",
        "notes": "Iterator chain for data transformation",
        "code": """\
pub fn top_words(text: &str, n: usize) -> Vec<(String, usize)> {
    let mut counts = std::collections::HashMap::new();
    text.split_whitespace()
        .map(|w| w.to_lowercase())
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| !w.is_empty() && w.len() > 2)
        .for_each(|w| *counts.entry(w).or_insert(0) += 1);

    let mut pairs: Vec<_> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs.truncate(n);
    pairs
}

pub fn running_sum(values: &[f64]) -> Vec<f64> {
    values
        .iter()
        .scan(0.0, |acc, &x| {
            *acc += x;
            Some(*acc)
        })
        .collect()
}
""",
    },
    {
        "id": "rust_ext_enum_dispatch",
        "language": "rust",
        "notes": "Enum-based dispatch, pattern matching",
        "code": """\
#[derive(Debug)]
pub enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
}

impl Shape {
    pub fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => std::f64::consts::PI * radius * radius,
            Shape::Rectangle { width, height } => width * height,
            Shape::Triangle { base, height } => 0.5 * base * height,
        }
    }

    pub fn perimeter(&self) -> f64 {
        match self {
            Shape::Circle { radius } => 2.0 * std::f64::consts::PI * radius,
            Shape::Rectangle { width, height } => 2.0 * (width + height),
            Shape::Triangle { base, height } => {
                let hyp = (base * base + height * height).sqrt();
                base + height + hyp
            }
        }
    }

    pub fn description(&self) -> String {
        match self {
            Shape::Circle { radius } => format!("Circle with radius {:.2}", radius),
            Shape::Rectangle { width, height } => {
                format!("Rectangle {}x{}", width, height)
            }
            Shape::Triangle { base, height } => {
                format!("Triangle base={:.2} height={:.2}", base, height)
            }
        }
    }
}
""",
    },
    {
        "id": "rust_ext_tokio_channel",
        "language": "rust",
        "notes": "Tokio mpsc channel for async message passing",
        "code": """\
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Command {
    Get { key: String, resp: mpsc::Sender<Option<String>> },
    Set { key: String, value: String },
    Delete { key: String },
}

pub async fn run_store(mut rx: mpsc::Receiver<Command>) {
    let mut store = std::collections::HashMap::new();

    while let Some(cmd) = rx.recv().await {
        match cmd {
            Command::Get { key, resp } => {
                let value = store.get(&key).cloned();
                let _ = resp.send(value).await;
            }
            Command::Set { key, value } => {
                store.insert(key, value);
            }
            Command::Delete { key } => {
                store.remove(&key);
            }
        }
    }
}
""",
    },
    {
        "id": "rust_ext_smart_pointers",
        "language": "rust",
        "notes": "Arc and Mutex for shared state, no unsafe",
        "code": """\
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[derive(Clone)]
pub struct SharedState {
    inner: Arc<Mutex<StateInner>>,
}

struct StateInner {
    counters: HashMap<String, u64>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StateInner {
                counters: HashMap::new(),
            })),
        }
    }

    pub fn increment(&self, key: &str) -> u64 {
        let mut state = self.inner.lock().expect("lock poisoned");
        let counter = state.counters.entry(key.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    pub fn get(&self, key: &str) -> u64 {
        let state = self.inner.lock().expect("lock poisoned");
        state.counters.get(key).copied().unwrap_or(0)
    }

    pub fn snapshot(&self) -> HashMap<String, u64> {
        let state = self.inner.lock().expect("lock poisoned");
        state.counters.clone()
    }
}
""",
    },
    {
        "id": "rust_ext_from_impl",
        "language": "rust",
        "notes": "From/Into implementations for type conversion",
        "code": """\
#[derive(Debug)]
pub struct Celsius(pub f64);

#[derive(Debug)]
pub struct Fahrenheit(pub f64);

#[derive(Debug)]
pub struct Kelvin(pub f64);

impl From<Celsius> for Fahrenheit {
    fn from(c: Celsius) -> Self {
        Fahrenheit(c.0 * 9.0 / 5.0 + 32.0)
    }
}

impl From<Celsius> for Kelvin {
    fn from(c: Celsius) -> Self {
        Kelvin(c.0 + 273.15)
    }
}

impl From<Fahrenheit> for Celsius {
    fn from(f: Fahrenheit) -> Self {
        Celsius((f.0 - 32.0) * 5.0 / 9.0)
    }
}

impl std::fmt::Display for Celsius {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}°C", self.0)
    }
}

impl std::fmt::Display for Fahrenheit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.1}°F", self.0)
    }
}
""",
    },
    {
        "id": "rust_ext_lifetime_refs",
        "language": "rust",
        "notes": "Proper lifetime annotations, borrowing",
        "code": """\
pub struct StringSplitter<'a> {
    remainder: &'a str,
    delimiter: &'a str,
}

impl<'a> StringSplitter<'a> {
    pub fn new(input: &'a str, delimiter: &'a str) -> Self {
        Self {
            remainder: input,
            delimiter,
        }
    }
}

impl<'a> Iterator for StringSplitter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remainder.is_empty() {
            return None;
        }
        match self.remainder.find(self.delimiter) {
            Some(pos) => {
                let item = &self.remainder[..pos];
                self.remainder = &self.remainder[pos + self.delimiter.len()..];
                Some(item)
            }
            None => {
                let item = self.remainder;
                self.remainder = "";
                Some(item)
            }
        }
    }
}
""",
    },
    {
        "id": "rust_ext_newtype_pattern",
        "language": "rust",
        "notes": "Newtype pattern for type safety",
        "code": """\
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderId(u64);

impl UserId {
    pub fn new(id: u64) -> Result<Self, &'static str> {
        if id == 0 {
            Err("user id must be positive")
        } else {
            Ok(Self(id))
        }
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl OrderId {
    pub fn new(id: u64) -> Result<Self, &'static str> {
        if id == 0 {
            Err("order id must be positive")
        } else {
            Ok(Self(id))
        }
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// These won't compile, preventing accidental misuse:
// fn get_order(user_id: UserId) { ... }
// get_order(order_id) // compile error!
""",
    },
    {
        "id": "rust_ext_file_io",
        "language": "rust",
        "notes": "Safe file I/O with proper error propagation",
        "code": """\
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

pub fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}

pub fn count_lines(path: &Path) -> io::Result<usize> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
}

pub fn write_lines(path: &Path, lines: &[&str]) -> io::Result<()> {
    let content = lines.join("\\n");
    fs::write(path, content)
}

pub fn ensure_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}
""",
    },
    {
        "id": "rust_ext_testing",
        "language": "rust",
        "notes": "Unit tests with assertions and test helpers",
        "code": """\
pub fn fibonacci(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut a: u64 = 0;
            let mut b: u64 = 1;
            for _ in 2..=n {
                let tmp = a + b;
                a = b;
                b = tmp;
            }
            b
        }
    }
}

pub fn is_palindrome(s: &str) -> bool {
    let chars: Vec<char> = s.chars().filter(|c| c.is_alphanumeric()).collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_lowercase().next().unwrap()).collect();
    lower == lower.iter().rev().copied().collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci() {
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
        assert_eq!(fibonacci(10), 55);
        assert_eq!(fibonacci(20), 6765);
    }

    #[test]
    fn test_palindrome() {
        assert!(is_palindrome("racecar"));
        assert!(is_palindrome("A man a plan a canal Panama"));
        assert!(!is_palindrome("hello"));
    }
}
""",
    },
    {
        "id": "rust_ext_generic_cache",
        "language": "rust",
        "notes": "Generic LRU-style cache with bounded capacity",
        "code": """\
use std::collections::HashMap;

pub struct BoundedCache<K, V> {
    capacity: usize,
    order: Vec<K>,
    map: HashMap<K, V>,
}

impl<K: Clone + Eq + std::hash::Hash, V> BoundedCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be positive");
        Self {
            capacity,
            order: Vec::with_capacity(capacity),
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.map.insert(key, value);
            return;
        }
        if self.order.len() >= self.capacity {
            let evicted = self.order.remove(0);
            self.map.remove(&evicted);
        }
        self.order.push(key.clone());
        self.map.insert(key, value);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
""",
    },
    {
        "id": "rust_ext_cli_args",
        "language": "rust",
        "notes": "CLI argument parsing with clap",
        "code": """\
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "processor", about = "Process data files")]
pub struct Args {
    /// Input file path
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Number of worker threads
    #[arg(short = 'j', long, default_value_t = 4)]
    pub threads: usize,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Processing format
    #[arg(long, default_value = "json")]
    pub format: String,
}

pub fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.verbose {
        eprintln!("Input: {}", args.input.display());
        eprintln!("Output: {}", args.output.display());
        eprintln!("Threads: {}", args.threads);
    }
    // processing logic here
    Ok(())
}
""",
    },
    {
        "id": "rust_ext_crypto_proper",
        "language": "rust",
        "notes": "Proper crypto with ring crate, no weak algorithms",
        "code": """\
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

pub fn sha256_hex(data: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, data);
    hash.as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf)?;
    Ok(buf)
}

pub fn generate_token() -> Result<String, ring::error::Unspecified> {
    let bytes = generate_random_bytes(32)?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}
""",
    },
    {
        "id": "rust_ext_middleware_tower",
        "language": "rust",
        "notes": "Tower-style middleware layer",
        "code": """\
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

pub struct TimingLayer;

pub struct TimingService<S> {
    inner: S,
}

impl<S> TimingService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

pub trait Service<Request> {
    type Response;
    type Error;
    type Future: Future<Output = Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request) -> Self::Future;
}

impl<S, Req> Service<Req> for TimingService<S>
where
    S: Service<Req>,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>>>>;

    fn call(&self, req: Req) -> Self::Future {
        let start = Instant::now();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let result = fut.await;
            eprintln!("request took {:?}", start.elapsed());
            result
        })
    }
}
""",
    },
    {
        "id": "rust_ext_env_config",
        "language": "rust",
        "notes": "Environment-based configuration loading",
        "code": """\
use std::env;

#[derive(Debug)]
pub struct AppConfig {
    pub database_url: String,
    pub port: u16,
    pub log_level: String,
    pub max_pool_size: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL must be set".to_string())?;

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|e| format!("invalid PORT: {}", e))?;

        let log_level = env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info".to_string());

        let max_pool_size = env::var("MAX_POOL_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u32>()
            .map_err(|e| format!("invalid MAX_POOL_SIZE: {}", e))?;

        Ok(Self {
            database_url,
            port,
            log_level,
            max_pool_size,
        })
    }
}
""",
    },
    {
        "id": "rust_ext_collection_ops",
        "language": "rust",
        "notes": "Collection operations with functional style",
        "code": """\
use std::collections::HashMap;

pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>
where
    K: Eq + std::hash::Hash,
    F: Fn(&T) -> K,
{
    let mut groups: HashMap<K, Vec<T>> = HashMap::new();
    for item in items {
        let key = key_fn(&item);
        groups.entry(key).or_default().push(item);
    }
    groups
}

pub fn partition<T, F>(items: Vec<T>, predicate: F) -> (Vec<T>, Vec<T>)
where
    F: Fn(&T) -> bool,
{
    let mut pass = Vec::new();
    let mut fail = Vec::new();
    for item in items {
        if predicate(&item) {
            pass.push(item);
        } else {
            fail.push(item);
        }
    }
    (pass, fail)
}

pub fn unique_by<T, K, F>(items: Vec<T>, key_fn: F) -> Vec<T>
where
    K: Eq + std::hash::Hash,
    F: Fn(&T) -> K,
{
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(key_fn(item)))
        .collect()
}
""",
    },

    # ─────────────────────── JAVA (25 samples) ────────────────────────────────
    {
        "id": "java_ext_rest_controller",
        "language": "java",
        "notes": "Spring REST controller with validation",
        "code": """\
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    public record CreateUserRequest(
        @NotBlank @Size(max = 100) String name,
        @Email @NotBlank String email
    ) {}

    public record UserResponse(long id, String name, String email) {}

    @PostMapping
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        var user = new UserResponse(1L, request.name(), request.email());
        return ResponseEntity.status(201).body(user);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable long id) {
        if (id <= 0) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(new UserResponse(id, "Alice", "alice@example.com"));
    }
}
""",
    },
    {
        "id": "java_ext_prepared_stmt",
        "language": "java",
        "notes": "JDBC PreparedStatement with parameterized queries",
        "code": """\
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UserRepository {
    private final Connection conn;

    public UserRepository(Connection conn) {
        this.conn = conn;
    }

    public Optional<String> findNameById(long id) throws SQLException {
        String sql = "SELECT name FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rs.getString("name"));
                }
                return Optional.empty();
            }
        }
    }

    public List<String> findActiveUserNames(int limit) throws SQLException {
        String sql = "SELECT name FROM users WHERE active = true ORDER BY name LIMIT ?";
        List<String> names = new ArrayList<>();
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, Math.min(limit, 1000));
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    names.add(rs.getString("name"));
                }
            }
        }
        return names;
    }
}
""",
    },
    {
        "id": "java_ext_record_types",
        "language": "java",
        "notes": "Java records with validation logic",
        "code": """\
import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record OrderItem(String productId, int quantity, double unitPrice) {
    public OrderItem {
        Objects.requireNonNull(productId, "productId must not be null");
        if (quantity <= 0) throw new IllegalArgumentException("quantity must be positive");
        if (unitPrice < 0) throw new IllegalArgumentException("unitPrice must not be negative");
    }

    public double total() {
        return quantity * unitPrice;
    }
}

record Order(String orderId, List<OrderItem> items, Instant createdAt) {
    public Order {
        Objects.requireNonNull(orderId);
        items = List.copyOf(items);  // defensive copy
    }

    public double grandTotal() {
        return items.stream().mapToDouble(OrderItem::total).sum();
    }

    public int totalItems() {
        return items.stream().mapToInt(OrderItem::quantity).sum();
    }
}
""",
    },
    {
        "id": "java_ext_completable_future",
        "language": "java",
        "notes": "CompletableFuture composition, async patterns",
        "code": """\
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AsyncService {
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public CompletableFuture<String> fetchUserProfile(long userId) {
        return CompletableFuture.supplyAsync(() -> {
            // simulate API call
            return "User-" + userId;
        }, executor);
    }

    public CompletableFuture<Integer> fetchOrderCount(long userId) {
        return CompletableFuture.supplyAsync(() -> {
            // simulate DB query
            return 42;
        }, executor);
    }

    public CompletableFuture<String> getUserSummary(long userId) {
        return fetchUserProfile(userId)
            .thenCombine(fetchOrderCount(userId),
                (profile, count) -> String.format("%s has %d orders", profile, count))
            .exceptionally(ex -> "Error: " + ex.getMessage());
    }

    public void shutdown() {
        executor.shutdown();
    }
}
""",
    },
    {
        "id": "java_ext_optional_chain",
        "language": "java",
        "notes": "Optional chaining for null safety",
        "code": """\
import java.util.Optional;

public class AddressService {
    public record Address(String street, String city, String zipCode, String country) {}
    public record Customer(String name, Address address) {}

    public Optional<String> getCity(Customer customer) {
        return Optional.ofNullable(customer)
            .map(Customer::address)
            .map(Address::city);
    }

    public String getFormattedAddress(Customer customer) {
        return Optional.ofNullable(customer)
            .map(Customer::address)
            .map(addr -> String.format("%s, %s %s, %s",
                addr.street(), addr.city(), addr.zipCode(), addr.country()))
            .orElse("No address on file");
    }

    public boolean isInCountry(Customer customer, String country) {
        return Optional.ofNullable(customer)
            .map(Customer::address)
            .map(Address::country)
            .map(c -> c.equalsIgnoreCase(country))
            .orElse(false);
    }
}
""",
    },
    {
        "id": "java_ext_sealed_interface",
        "language": "java",
        "notes": "Sealed interfaces with pattern matching",
        "code": """\
public sealed interface PaymentMethod permits CreditCard, BankTransfer, DigitalWallet {
    String displayName();
    boolean isValid();
}

record CreditCard(String number, String expiry, String cvv) implements PaymentMethod {
    @Override
    public String displayName() {
        return "Card ending in " + number.substring(number.length() - 4);
    }

    @Override
    public boolean isValid() {
        return number.length() >= 13 && number.length() <= 19
            && expiry.matches("\\\\d{2}/\\\\d{2}")
            && cvv.matches("\\\\d{3,4}");
    }
}

record BankTransfer(String iban, String bic) implements PaymentMethod {
    @Override
    public String displayName() {
        return "Bank transfer to " + iban.substring(0, 4) + "...";
    }

    @Override
    public boolean isValid() {
        return iban.length() >= 15 && bic.length() >= 8;
    }
}

record DigitalWallet(String provider, String accountId) implements PaymentMethod {
    @Override
    public String displayName() {
        return provider + " wallet";
    }

    @Override
    public boolean isValid() {
        return !provider.isBlank() && !accountId.isBlank();
    }
}
""",
    },
    {
        "id": "java_ext_generics_bounded",
        "language": "java",
        "notes": "Bounded generics with comparable, type-safe operations",
        "code": """\
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class CollectionUtils {

    public static <T extends Comparable<T>> T max(List<T> items) {
        if (items.isEmpty()) throw new IllegalArgumentException("empty list");
        T result = items.get(0);
        for (int i = 1; i < items.size(); i++) {
            if (items.get(i).compareTo(result) > 0) {
                result = items.get(i);
            }
        }
        return result;
    }

    public static <T> List<T> topN(List<T> items, int n, Comparator<T> comparator) {
        List<T> sorted = new ArrayList<>(items);
        sorted.sort(comparator.reversed());
        return Collections.unmodifiableList(sorted.subList(0, Math.min(n, sorted.size())));
    }

    public static <T> List<List<T>> partition(List<T> items, int size) {
        if (size <= 0) throw new IllegalArgumentException("size must be positive");
        List<List<T>> result = new ArrayList<>();
        for (int i = 0; i < items.size(); i += size) {
            result.add(items.subList(i, Math.min(i + size, items.size())));
        }
        return result;
    }
}
""",
    },
    {
        "id": "java_ext_exception_handling",
        "language": "java",
        "notes": "Custom exceptions with proper hierarchy",
        "code": """\
public class ServiceException extends RuntimeException {
    private final String errorCode;

    public ServiceException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ServiceException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}

class NotFoundException extends ServiceException {
    public NotFoundException(String resource, String id) {
        super("NOT_FOUND", String.format("%s with id '%s' not found", resource, id));
    }
}

class ValidationException extends ServiceException {
    private final java.util.List<String> errors;

    public ValidationException(java.util.List<String> errors) {
        super("VALIDATION_ERROR", "Validation failed: " + String.join(", ", errors));
        this.errors = java.util.List.copyOf(errors);
    }

    public java.util.List<String> getErrors() {
        return errors;
    }
}
""",
    },
    {
        "id": "java_ext_enum_strategy",
        "language": "java",
        "notes": "Enum with behavior, strategy pattern",
        "code": """\
import java.math.BigDecimal;
import java.math.RoundingMode;

public enum TaxStrategy {
    US {
        @Override
        public BigDecimal calculate(BigDecimal amount) {
            return amount.multiply(new BigDecimal("0.0725")).setScale(2, RoundingMode.HALF_UP);
        }
    },
    EU {
        @Override
        public BigDecimal calculate(BigDecimal amount) {
            return amount.multiply(new BigDecimal("0.20")).setScale(2, RoundingMode.HALF_UP);
        }
    },
    EXEMPT {
        @Override
        public BigDecimal calculate(BigDecimal amount) {
            return BigDecimal.ZERO;
        }
    };

    public abstract BigDecimal calculate(BigDecimal amount);

    public BigDecimal addTax(BigDecimal amount) {
        return amount.add(calculate(amount));
    }
}
""",
    },
    {
        "id": "java_ext_concurrent_map",
        "language": "java",
        "notes": "Thread-safe operations with ConcurrentHashMap",
        "code": """\
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class MetricsCollector {
    private final ConcurrentHashMap<String, AtomicLong> counters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> gauges = new ConcurrentHashMap<>();

    public void incrementCounter(String name) {
        counters.computeIfAbsent(name, k -> new AtomicLong()).incrementAndGet();
    }

    public void incrementCounter(String name, long delta) {
        counters.computeIfAbsent(name, k -> new AtomicLong()).addAndGet(delta);
    }

    public long getCounter(String name) {
        AtomicLong counter = counters.get(name);
        return counter != null ? counter.get() : 0L;
    }

    public void setGauge(String name, long value) {
        gauges.computeIfAbsent(name, k -> new AtomicLong()).set(value);
    }

    public java.util.Map<String, Long> snapshot() {
        var result = new java.util.HashMap<String, Long>();
        counters.forEach((k, v) -> result.put("counter." + k, v.get()));
        gauges.forEach((k, v) -> result.put("gauge." + k, v.get()));
        return java.util.Collections.unmodifiableMap(result);
    }
}
""",
    },
    {
        "id": "java_ext_file_processing",
        "language": "java",
        "notes": "File processing with try-with-resources and NIO",
        "code": """\
import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FileProcessor {

    public List<String> readNonEmptyLines(Path path) throws IOException {
        try (Stream<String> lines = Files.lines(path)) {
            return lines
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .collect(Collectors.toUnmodifiableList());
        }
    }

    public long countMatches(Path path, String pattern) throws IOException {
        try (Stream<String> lines = Files.lines(path)) {
            return lines.filter(line -> line.contains(pattern)).count();
        }
    }

    public void copyWithBackup(Path source, Path dest) throws IOException {
        if (Files.exists(dest)) {
            Path backup = dest.resolveSibling(dest.getFileName() + ".bak");
            Files.copy(dest, backup, StandardCopyOption.REPLACE_EXISTING);
        }
        Files.copy(source, dest, StandardCopyOption.REPLACE_EXISTING);
    }
}
""",
    },
    {
        "id": "java_ext_interface_default",
        "language": "java",
        "notes": "Interface with default methods for composable behavior",
        "code": """\
import java.util.function.Predicate;

public interface Specification<T> {
    boolean isSatisfiedBy(T candidate);

    default Specification<T> and(Specification<T> other) {
        return candidate -> this.isSatisfiedBy(candidate) && other.isSatisfiedBy(candidate);
    }

    default Specification<T> or(Specification<T> other) {
        return candidate -> this.isSatisfiedBy(candidate) || other.isSatisfiedBy(candidate);
    }

    default Specification<T> not() {
        return candidate -> !this.isSatisfiedBy(candidate);
    }

    static <T> Specification<T> from(Predicate<T> predicate) {
        return predicate::test;
    }
}

// Usage example:
// Specification<User> isActive = u -> u.isActive();
// Specification<User> isAdmin = u -> u.getRole().equals("admin");
// Specification<User> activeAdmin = isActive.and(isAdmin);
""",
    },
    {
        "id": "java_ext_http_client",
        "language": "java",
        "notes": "Java HttpClient with proper timeout and error handling",
        "code": """\
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.io.IOException;

public class ApiClient {
    private final HttpClient client;
    private final String baseUrl;

    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    public String get(String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(30))
            .header("Accept", "application/json")
            .GET()
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 400) {
            throw new IOException("HTTP " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }
}
""",
    },
    {
        "id": "java_ext_testing_junit",
        "language": "java",
        "notes": "JUnit 5 tests with assertions and parameterized tests",
        "code": """\
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

class CalculatorTest {

    static int add(int a, int b) { return a + b; }
    static int multiply(int a, int b) { return a * b; }

    @ParameterizedTest
    @CsvSource({
        "1, 2, 3",
        "-1, 1, 0",
        "0, 0, 0",
        "100, 200, 300"
    })
    void testAdd(int a, int b, int expected) {
        assertEquals(expected, add(a, b));
    }

    @Test
    void testMultiply() {
        assertEquals(6, multiply(2, 3));
        assertEquals(0, multiply(0, 100));
        assertEquals(-6, multiply(-2, 3));
    }

    @Test
    void testAddDoesNotOverflow() {
        assertDoesNotThrow(() -> add(Integer.MAX_VALUE - 1, 1));
    }
}
""",
    },
    {
        "id": "java_ext_immutable_collection",
        "language": "java",
        "notes": "Immutable collections and defensive copying",
        "code": """\
import java.util.*;

public final class Team {
    private final String name;
    private final List<String> members;
    private final Map<String, String> metadata;

    public Team(String name, List<String> members, Map<String, String> metadata) {
        this.name = Objects.requireNonNull(name);
        this.members = List.copyOf(members);
        this.metadata = Map.copyOf(metadata);
    }

    public String getName() { return name; }
    public List<String> getMembers() { return members; }
    public Map<String, String> getMetadata() { return metadata; }

    public Team addMember(String member) {
        var newMembers = new ArrayList<>(members);
        newMembers.add(member);
        return new Team(name, newMembers, metadata);
    }

    public Team withMetadata(String key, String value) {
        var newMeta = new HashMap<>(metadata);
        newMeta.put(key, value);
        return new Team(name, members, newMeta);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Team t)) return false;
        return name.equals(t.name) && members.equals(t.members);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, members);
    }
}
""",
    },
    {
        "id": "java_ext_event_listener",
        "language": "java",
        "notes": "Type-safe event listener pattern",
        "code": """\
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class EventBus {
    private final Map<Class<?>, List<Consumer<?>>> listeners = new HashMap<>();

    public <T> void subscribe(Class<T> eventType, Consumer<T> handler) {
        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(handler);
    }

    @SuppressWarnings("unchecked")
    public <T> void publish(T event) {
        List<Consumer<?>> handlers = listeners.get(event.getClass());
        if (handlers != null) {
            for (Consumer<?> handler : handlers) {
                ((Consumer<T>) handler).accept(event);
            }
        }
    }

    public <T> void unsubscribeAll(Class<T> eventType) {
        listeners.remove(eventType);
    }
}

// Events
record UserCreated(long userId, String name) {}
record OrderPlaced(long orderId, long userId, double total) {}
""",
    },
    {
        "id": "java_ext_config_properties",
        "language": "java",
        "notes": "Configuration from environment variables with defaults",
        "code": """\
import java.util.Objects;
import java.util.Optional;

public final class AppConfig {
    private final int port;
    private final String dbUrl;
    private final String logLevel;
    private final boolean debug;

    private AppConfig(int port, String dbUrl, String logLevel, boolean debug) {
        this.port = port;
        this.dbUrl = Objects.requireNonNull(dbUrl);
        this.logLevel = logLevel;
        this.debug = debug;
    }

    public static AppConfig fromEnv() {
        String dbUrl = Optional.ofNullable(System.getenv("DATABASE_URL"))
            .orElseThrow(() -> new IllegalStateException("DATABASE_URL is required"));

        int port = Optional.ofNullable(System.getenv("PORT"))
            .map(Integer::parseInt)
            .orElse(8080);

        String logLevel = Optional.ofNullable(System.getenv("LOG_LEVEL"))
            .orElse("INFO");

        boolean debug = "true".equalsIgnoreCase(System.getenv("DEBUG"));

        return new AppConfig(port, dbUrl, logLevel, debug);
    }

    public int port() { return port; }
    public String dbUrl() { return dbUrl; }
    public String logLevel() { return logLevel; }
    public boolean debug() { return debug; }
}
""",
    },
    {
        "id": "java_ext_rate_limiter",
        "language": "java",
        "notes": "Token bucket rate limiter, thread-safe",
        "code": """\
import java.util.concurrent.atomic.AtomicLong;

public class TokenBucketRateLimiter {
    private final long maxTokens;
    private final long refillRatePerSecond;
    private final AtomicLong tokens;
    private volatile long lastRefillTimestamp;

    public TokenBucketRateLimiter(long maxTokens, long refillRatePerSecond) {
        this.maxTokens = maxTokens;
        this.refillRatePerSecond = refillRatePerSecond;
        this.tokens = new AtomicLong(maxTokens);
        this.lastRefillTimestamp = System.nanoTime();
    }

    public synchronized boolean tryAcquire() {
        refill();
        long current = tokens.get();
        if (current > 0) {
            tokens.decrementAndGet();
            return true;
        }
        return false;
    }

    private void refill() {
        long now = System.nanoTime();
        long elapsed = now - lastRefillTimestamp;
        long tokensToAdd = elapsed * refillRatePerSecond / 1_000_000_000L;
        if (tokensToAdd > 0) {
            long newTokens = Math.min(maxTokens, tokens.get() + tokensToAdd);
            tokens.set(newTokens);
            lastRefillTimestamp = now;
        }
    }

    public long availableTokens() {
        return tokens.get();
    }
}
""",
    },
    {
        "id": "java_ext_retry_pattern",
        "language": "java",
        "notes": "Retry pattern with exponential backoff",
        "code": """\
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.function.Predicate;

public class Retry {
    private final int maxAttempts;
    private final Duration initialDelay;
    private final double multiplier;
    private final Predicate<Exception> retryOn;

    private Retry(int maxAttempts, Duration initialDelay, double multiplier, Predicate<Exception> retryOn) {
        this.maxAttempts = maxAttempts;
        this.initialDelay = initialDelay;
        this.multiplier = multiplier;
        this.retryOn = retryOn;
    }

    public static Retry withDefaults() {
        return new Retry(3, Duration.ofMillis(100), 2.0, e -> true);
    }

    public Retry maxAttempts(int n) {
        return new Retry(n, initialDelay, multiplier, retryOn);
    }

    public Retry initialDelay(Duration d) {
        return new Retry(maxAttempts, d, multiplier, retryOn);
    }

    public <T> T execute(Callable<T> task) throws Exception {
        Exception lastException = null;
        long delay = initialDelay.toMillis();

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                return task.call();
            } catch (Exception e) {
                lastException = e;
                if (!retryOn.test(e) || attempt == maxAttempts - 1) throw e;
                Thread.sleep(delay);
                delay = (long) (delay * multiplier);
            }
        }
        throw lastException;
    }
}
""",
    },
    {
        "id": "java_ext_observer_pattern",
        "language": "java",
        "notes": "Observer pattern with generics",
        "code": """\
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class Observable<T> {
    private T value;
    private final List<Consumer<T>> observers = new CopyOnWriteArrayList<>();

    public Observable(T initialValue) {
        this.value = initialValue;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T newValue) {
        this.value = newValue;
        notifyObservers();
    }

    public Runnable subscribe(Consumer<T> observer) {
        observers.add(observer);
        observer.accept(value); // emit current value
        return () -> observers.remove(observer);
    }

    private void notifyObservers() {
        for (Consumer<T> observer : observers) {
            observer.accept(value);
        }
    }
}
""",
    },
    {
        "id": "java_ext_encryption_proper",
        "language": "java",
        "notes": "Proper AES-GCM encryption, no weak algorithms",
        "code": """\
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Encryptor {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public Encryptor(SecretKey key) {
        this.key = key;
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }

    public String encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public byte[] decrypt(String encoded) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encoded);
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        byte[] ciphertext = new byte[combined.length - iv.length];
        System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        return cipher.doFinal(ciphertext);
    }
}
""",
    },

    # ─────────────────────── ADDITIONAL PYTHON (5 samples) ────────────────────
    {
        "id": "py_ext_decorator_stack",
        "language": "python",
        "notes": "Stacked decorators with proper functools.wraps",
        "code": """\
from __future__ import annotations
import functools
import logging
import time
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])
logger = logging.getLogger(__name__)


def log_calls(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger.info("Calling %s", func.__name__)
        result = func(*args, **kwargs)
        logger.info("Finished %s", func.__name__)
        return result
    return wrapper  # type: ignore[return-value]


def timing(func: F) -> F:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.debug("%s took %.3fs", func.__name__, elapsed)
        return result
    return wrapper  # type: ignore[return-value]
""",
    },
    {
        "id": "py_ext_contextvar",
        "language": "python",
        "notes": "contextvars for request-scoped state",
        "code": """\
from __future__ import annotations
import contextvars
import uuid
from typing import Any

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
current_user_var: contextvars.ContextVar[dict | None] = contextvars.ContextVar("current_user", default=None)


def init_request_context() -> str:
    rid = str(uuid.uuid4())[:8]
    request_id_var.set(rid)
    return rid


def get_request_id() -> str:
    return request_id_var.get()


def set_current_user(user: dict) -> None:
    current_user_var.set(user)


def get_current_user() -> dict | None:
    return current_user_var.get()
""",
    },
    {
        "id": "py_ext_abc_plugin",
        "language": "python",
        "notes": "ABC-based plugin interface, no dynamic eval",
        "code": """\
from __future__ import annotations
from abc import ABC, abstractmethod


class Exporter(ABC):
    @abstractmethod
    def export(self, data: list[dict]) -> bytes:
        ...

    @abstractmethod
    def content_type(self) -> str:
        ...


class CsvExporter(Exporter):
    def export(self, data: list[dict]) -> bytes:
        if not data:
            return b""
        headers = list(data[0].keys())
        lines = [",".join(headers)]
        for row in data:
            lines.append(",".join(str(row.get(h, "")) for h in headers))
        return "\\n".join(lines).encode("utf-8")

    def content_type(self) -> str:
        return "text/csv"


class JsonExporter(Exporter):
    def export(self, data: list[dict]) -> bytes:
        import json
        return json.dumps(data, default=str).encode("utf-8")

    def content_type(self) -> str:
        return "application/json"
""",
    },
    {
        "id": "py_ext_dataclass_frozen",
        "language": "python",
        "notes": "Frozen dataclass for immutable value objects",
        "code": """\
from __future__ import annotations
from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True)
class Money:
    amount: int  # cents
    currency: str

    def add(self, other: Money) -> Money:
        if self.currency != other.currency:
            raise ValueError(f"Cannot add {self.currency} and {other.currency}")
        return Money(self.amount + other.amount, self.currency)

    def subtract(self, other: Money) -> Money:
        if self.currency != other.currency:
            raise ValueError(f"Cannot subtract {self.currency} and {other.currency}")
        return Money(self.amount - other.amount, self.currency)

    def multiply(self, factor: int) -> Money:
        return Money(self.amount * factor, self.currency)

    def display(self) -> str:
        whole = self.amount // 100
        frac = abs(self.amount) % 100
        return f"{self.currency} {whole}.{frac:02d}"
""",
    },
    {
        "id": "py_ext_httpx_client",
        "language": "python",
        "notes": "httpx async client with retries, no secrets in source",
        "code": """\
from __future__ import annotations
import httpx


async def fetch_json(url: str, timeout: float = 10.0) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        return response.json()


async def post_json(url: str, payload: dict, token: str) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()
""",
    },

    # ─────────────────────── ADDITIONAL JAVASCRIPT (5 samples) ────────────────
    {
        "id": "js_ext_abort_controller",
        "language": "javascript",
        "notes": "AbortController for cancellable operations",
        "code": """\
class CancellableTask {
  #controller = null;

  start(asyncFn) {
    this.cancel();
    this.#controller = new AbortController();
    const { signal } = this.#controller;

    return asyncFn(signal).catch((err) => {
      if (err.name === 'AbortError') return null;
      throw err;
    });
  }

  cancel() {
    this.#controller?.abort();
    this.#controller = null;
  }

  get isRunning() {
    return this.#controller !== null && !this.#controller.signal.aborted;
  }
}

module.exports = { CancellableTask };
""",
    },
    {
        "id": "js_ext_lru_cache",
        "language": "javascript",
        "notes": "LRU cache with Map for O(1) operations",
        "code": """\
class LRUCache {
  #capacity;
  #cache = new Map();

  constructor(capacity) {
    this.#capacity = capacity;
  }

  get(key) {
    if (!this.#cache.has(key)) return undefined;
    const value = this.#cache.get(key);
    this.#cache.delete(key);
    this.#cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.#cache.has(key)) this.#cache.delete(key);
    this.#cache.set(key, value);
    if (this.#cache.size > this.#capacity) {
      const oldest = this.#cache.keys().next().value;
      this.#cache.delete(oldest);
    }
  }

  get size() { return this.#cache.size; }
  has(key) { return this.#cache.has(key); }
  clear() { this.#cache.clear(); }
}

module.exports = { LRUCache };
""",
    },
    {
        "id": "js_ext_rate_limiter_middleware",
        "language": "javascript",
        "notes": "Express rate limiter middleware with in-memory store",
        "code": """\
function createRateLimiter({ windowMs = 60000, max = 100 } = {}) {
  const store = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (now - entry.resetTime > windowMs) store.delete(key);
    }
  }, windowMs);

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    let entry = store.get(key);

    if (!entry || now - entry.resetTime > windowMs) {
      entry = { count: 0, resetTime: now };
      store.set(key, entry);
    }

    entry.count++;

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));

    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests' });
    }

    next();
  };
}

module.exports = { createRateLimiter };
""",
    },
    {
        "id": "js_ext_deep_freeze",
        "language": "javascript",
        "notes": "Deep freeze utility for immutable config objects",
        "code": """\
function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const value of Object.values(obj)) {
    if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
      deepFreeze(value);
    }
  }
  return obj;
}

function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function merge(target, ...sources) {
  for (const source of sources) {
    for (const [key, value] of Object.entries(source)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        target[key] = merge(target[key] || {}, value);
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

module.exports = { deepFreeze, deepClone, merge };
""",
    },
    {
        "id": "js_ext_async_queue",
        "language": "javascript",
        "notes": "Async task queue with concurrency control",
        "code": """\
class AsyncQueue {
  #concurrency;
  #running = 0;
  #queue = [];

  constructor(concurrency = 5) {
    this.#concurrency = concurrency;
  }

  add(task) {
    return new Promise((resolve, reject) => {
      this.#queue.push({ task, resolve, reject });
      this.#process();
    });
  }

  #process() {
    while (this.#running < this.#concurrency && this.#queue.length > 0) {
      const { task, resolve, reject } = this.#queue.shift();
      this.#running++;
      task()
        .then(resolve)
        .catch(reject)
        .finally(() => {
          this.#running--;
          this.#process();
        });
    }
  }

  get pending() { return this.#queue.length; }
  get running() { return this.#running; }
}

module.exports = { AsyncQueue };
""",
    },

    # ─────────────────────── ADDITIONAL TYPESCRIPT (10 samples) ───────────────
    {
        "id": "ts_ext_mapped_types",
        "language": "typescript",
        "notes": "Advanced mapped and conditional types",
        "code": """\
type DeepReadonly<T> = {
  readonly [K in keyof T]: T[K] extends object ? DeepReadonly<T[K]> : T[K];
};

type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
type Required<T, K extends keyof T> = Omit<T, K> & globalThis.Required<Pick<T, K>>;

interface User {
  id: string;
  name: string;
  email: string;
  settings: {
    theme: string;
    notifications: boolean;
  };
}

type ReadonlyUser = DeepReadonly<User>;
type CreateUser = Optional<User, 'id'>;

function freeze<T extends object>(obj: T): DeepReadonly<T> {
  return Object.freeze(obj) as DeepReadonly<T>;
}

export { DeepReadonly, Optional, ReadonlyUser, CreateUser, freeze };
""",
    },
    {
        "id": "ts_ext_type_guards",
        "language": "typescript",
        "notes": "User-defined type guards for runtime validation",
        "code": """\
interface ApiError {
  code: number;
  message: string;
  details?: string[];
}

interface ApiSuccess<T> {
  data: T;
  meta?: Record<string, unknown>;
}

type ApiResult<T> = ApiSuccess<T> | ApiError;

function isApiError(result: ApiResult<unknown>): result is ApiError {
  return 'code' in result && 'message' in result;
}

function isApiSuccess<T>(result: ApiResult<T>): result is ApiSuccess<T> {
  return 'data' in result;
}

function handleResult<T>(result: ApiResult<T>): T {
  if (isApiError(result)) {
    throw new Error(`API Error ${result.code}: ${result.message}`);
  }
  return result.data;
}

export { ApiError, ApiSuccess, ApiResult, isApiError, isApiSuccess, handleResult };
""",
    },
    {
        "id": "ts_ext_decorator_pattern",
        "language": "typescript",
        "notes": "Class-based decorator pattern, no eval",
        "code": """\
interface Logger {
  log(level: string, message: string): void;
}

class ConsoleLogger implements Logger {
  log(level: string, message: string): void {
    console.log(`[${level.toUpperCase()}] ${message}`);
  }
}

class TimestampLogger implements Logger {
  constructor(private inner: Logger) {}

  log(level: string, message: string): void {
    const ts = new Date().toISOString();
    this.inner.log(level, `${ts} ${message}`);
  }
}

class FilteredLogger implements Logger {
  constructor(
    private inner: Logger,
    private minLevel: string,
  ) {}

  private levels = ['debug', 'info', 'warn', 'error'];

  log(level: string, message: string): void {
    if (this.levels.indexOf(level) >= this.levels.indexOf(this.minLevel)) {
      this.inner.log(level, message);
    }
  }
}

export { Logger, ConsoleLogger, TimestampLogger, FilteredLogger };
""",
    },
    {
        "id": "ts_ext_generic_pool",
        "language": "typescript",
        "notes": "Generic resource pool with acquire/release",
        "code": """\
class ResourcePool<T> {
  private available: T[] = [];
  private inUse = new Set<T>();
  private waitQueue: Array<(resource: T) => void> = [];

  constructor(
    private factory: () => T,
    private maxSize: number,
  ) {}

  async acquire(): Promise<T> {
    if (this.available.length > 0) {
      const resource = this.available.pop()!;
      this.inUse.add(resource);
      return resource;
    }

    if (this.inUse.size < this.maxSize) {
      const resource = this.factory();
      this.inUse.add(resource);
      return resource;
    }

    return new Promise<T>((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  release(resource: T): void {
    this.inUse.delete(resource);
    if (this.waitQueue.length > 0) {
      const resolve = this.waitQueue.shift()!;
      this.inUse.add(resource);
      resolve(resource);
    } else {
      this.available.push(resource);
    }
  }

  get size(): number { return this.inUse.size + this.available.length; }
  get activeCount(): number { return this.inUse.size; }
}

export { ResourcePool };
""",
    },
    {
        "id": "ts_ext_pub_sub",
        "language": "typescript",
        "notes": "Type-safe publish/subscribe message bus",
        "code": """\
type EventMap = Record<string, unknown>;
type Handler<T> = (payload: T) => void;

class PubSub<Events extends EventMap> {
  private handlers = new Map<keyof Events, Set<Handler<any>>>();

  on<K extends keyof Events>(event: K, handler: Handler<Events[K]>): () => void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler);
    return () => this.off(event, handler);
  }

  off<K extends keyof Events>(event: K, handler: Handler<Events[K]>): void {
    this.handlers.get(event)?.delete(handler);
  }

  emit<K extends keyof Events>(event: K, payload: Events[K]): void {
    this.handlers.get(event)?.forEach((handler) => handler(payload));
  }

  clear(): void {
    this.handlers.clear();
  }
}

// Usage:
// interface AppEvents { 'user:login': { userId: string }; 'order:placed': { orderId: string } }
// const bus = new PubSub<AppEvents>();

export { PubSub, EventMap, Handler };
""",
    },
    {
        "id": "ts_ext_pipe_function",
        "language": "typescript",
        "notes": "Type-safe pipe/compose utility functions",
        "code": """\
type UnaryFn<A, B> = (a: A) => B;

function pipe<A, B>(a: A, ab: UnaryFn<A, B>): B;
function pipe<A, B, C>(a: A, ab: UnaryFn<A, B>, bc: UnaryFn<B, C>): C;
function pipe<A, B, C, D>(a: A, ab: UnaryFn<A, B>, bc: UnaryFn<B, C>, cd: UnaryFn<C, D>): D;
function pipe(value: unknown, ...fns: UnaryFn<unknown, unknown>[]): unknown {
  return fns.reduce((acc, fn) => fn(acc), value);
}

function compose<A, B>(ab: UnaryFn<A, B>): UnaryFn<A, B>;
function compose<A, B, C>(bc: UnaryFn<B, C>, ab: UnaryFn<A, B>): UnaryFn<A, C>;
function compose(...fns: UnaryFn<any, any>[]): UnaryFn<any, any> {
  return (value) => fns.reduceRight((acc, fn) => fn(acc), value);
}

const double = (n: number) => n * 2;
const increment = (n: number) => n + 1;
const toString = (n: number) => String(n);

// pipe(5, double, increment, toString) => "11"

export { pipe, compose };
""",
    },
    {
        "id": "ts_ext_retry_async",
        "language": "typescript",
        "notes": "Async retry utility with type-safe options",
        "code": """\
interface RetryOptions {
  maxAttempts: number;
  delayMs: number;
  backoffFactor: number;
  maxDelayMs: number;
}

const defaultOptions: RetryOptions = {
  maxAttempts: 3,
  delayMs: 100,
  backoffFactor: 2,
  maxDelayMs: 10000,
};

async function retry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {},
): Promise<T> {
  const opts = { ...defaultOptions, ...options };
  let lastError: Error | undefined;
  let delay = opts.delayMs;

  for (let attempt = 0; attempt < opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < opts.maxAttempts - 1) {
        await new Promise((r) => setTimeout(r, delay));
        delay = Math.min(delay * opts.backoffFactor, opts.maxDelayMs);
      }
    }
  }

  throw lastError;
}

export { retry, RetryOptions };
""",
    },
    {
        "id": "ts_ext_immutable_update",
        "language": "typescript",
        "notes": "Immutable state update helpers",
        "code": """\
type RecursivePartial<T> = {
  [K in keyof T]?: T[K] extends object ? RecursivePartial<T[K]> : T[K];
};

function updateIn<T extends Record<string, unknown>>(
  obj: T,
  updates: RecursivePartial<T>,
): T {
  const result = { ...obj };
  for (const key of Object.keys(updates) as Array<keyof T>) {
    const update = updates[key];
    const current = obj[key];
    if (
      update !== null &&
      typeof update === 'object' &&
      !Array.isArray(update) &&
      typeof current === 'object' &&
      current !== null
    ) {
      result[key] = updateIn(
        current as Record<string, unknown>,
        update as RecursivePartial<Record<string, unknown>>,
      ) as T[keyof T];
    } else {
      result[key] = update as T[keyof T];
    }
  }
  return result;
}

function removeKey<T extends Record<string, unknown>, K extends keyof T>(
  obj: T,
  key: K,
): Omit<T, K> {
  const { [key]: _, ...rest } = obj;
  return rest as Omit<T, K>;
}

export { RecursivePartial, updateIn, removeKey };
""",
    },
    {
        "id": "ts_ext_next_api_route",
        "language": "typescript",
        "notes": "Next.js API route handler with validation",
        "code": """\
import { NextRequest, NextResponse } from 'next/server';

interface CreatePostBody {
  title: string;
  content: string;
  tags?: string[];
}

function validateBody(body: unknown): body is CreatePostBody {
  if (typeof body !== 'object' || body === null) return false;
  const obj = body as Record<string, unknown>;
  if (typeof obj.title !== 'string' || obj.title.length === 0) return false;
  if (typeof obj.content !== 'string') return false;
  if (obj.tags !== undefined && !Array.isArray(obj.tags)) return false;
  return true;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json();
    if (!validateBody(body)) {
      return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
    }

    const post = {
      id: crypto.randomUUID(),
      title: body.title.slice(0, 200),
      content: body.content.slice(0, 10000),
      tags: (body.tags ?? []).slice(0, 10),
      createdAt: new Date().toISOString(),
    };

    return NextResponse.json(post, { status: 201 });
  } catch {
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
""",
    },
    {
        "id": "ts_ext_graphql_resolver",
        "language": "typescript",
        "notes": "GraphQL resolver with proper typing",
        "code": """\
interface Context {
  userId: string | null;
  db: {
    users: { findById(id: string): Promise<User | null> };
    posts: { findByAuthor(authorId: string, limit: number): Promise<Post[]> };
  };
}

interface User {
  id: string;
  name: string;
  email: string;
}

interface Post {
  id: string;
  title: string;
  authorId: string;
}

const resolvers = {
  Query: {
    me: async (_: unknown, __: unknown, ctx: Context): Promise<User | null> => {
      if (!ctx.userId) return null;
      return ctx.db.users.findById(ctx.userId);
    },

    user: async (_: unknown, args: { id: string }, ctx: Context): Promise<User | null> => {
      return ctx.db.users.findById(args.id);
    },
  },

  User: {
    posts: async (parent: User, args: { limit?: number }, ctx: Context): Promise<Post[]> => {
      return ctx.db.posts.findByAuthor(parent.id, args.limit ?? 10);
    },
  },
};

export { resolvers, Context };
""",
    },

    # ─────────────────────── ADDITIONAL GO (5 samples) ────────────────────────
    {
        "id": "go_ext_generic_sort",
        "language": "go",
        "notes": "Generic sort and search with type constraints",
        "code": """\
package sliceutil

import (
\t"cmp"
\t"slices"
)

func SortBy[T any, K cmp.Ordered](items []T, keyFn func(T) K) []T {
\tresult := make([]T, len(items))
\tcopy(result, items)
\tslices.SortFunc(result, func(a, b T) int {
\t\treturn cmp.Compare(keyFn(a), keyFn(b))
\t})
\treturn result
}

func Unique[T comparable](items []T) []T {
\tseen := make(map[T]struct{}, len(items))
\tresult := make([]T, 0, len(items))
\tfor _, item := range items {
\t\tif _, ok := seen[item]; !ok {
\t\t\tseen[item] = struct{}{}
\t\t\tresult = append(result, item)
\t\t}
\t}
\treturn result
}

func Contains[T comparable](items []T, target T) bool {
\tfor _, item := range items {
\t\tif item == target {
\t\t\treturn true
\t\t}
\t}
\treturn false
}

func Map[T any, U any](items []T, fn func(T) U) []U {
\tresult := make([]U, len(items))
\tfor i, item := range items {
\t\tresult[i] = fn(item)
\t}
\treturn result
}
""",
    },
    {
        "id": "go_ext_grpc_server",
        "language": "go",
        "notes": "gRPC service registration pattern",
        "code": """\
package server

import (
\t"context"
\t"log"
)

type HealthService struct{}

type HealthCheckResponse struct {
\tStatus string
}

func (s *HealthService) Check(ctx context.Context) (*HealthCheckResponse, error) {
\tselect {
\tcase <-ctx.Done():
\t\treturn nil, ctx.Err()
\tdefault:
\t\treturn &HealthCheckResponse{Status: "SERVING"}, nil
\t}
}

type Service interface {
\tName() string
\tStart(ctx context.Context) error
\tStop(ctx context.Context) error
}

type ServiceRegistry struct {
\tservices []Service
}

func (r *ServiceRegistry) Register(s Service) {
\tr.services = append(r.services, s)
}

func (r *ServiceRegistry) StartAll(ctx context.Context) error {
\tfor _, s := range r.services {
\t\tlog.Printf("starting service: %s", s.Name())
\t\tif err := s.Start(ctx); err != nil {
\t\t\treturn err
\t\t}
\t}
\treturn nil
}
""",
    },
    {
        "id": "go_ext_rate_limiter",
        "language": "go",
        "notes": "Token bucket rate limiter with proper synchronization",
        "code": """\
package ratelimit

import (
\t"sync"
\t"time"
)

type TokenBucket struct {
\tmu         sync.Mutex
\ttokens     float64
\tmax        float64
\trefillRate float64
\tlastRefill time.Time
}

func NewTokenBucket(maxTokens float64, refillPerSecond float64) *TokenBucket {
\treturn &TokenBucket{
\t\ttokens:     maxTokens,
\t\tmax:        maxTokens,
\t\trefillRate: refillPerSecond,
\t\tlastRefill: time.Now(),
\t}
}

func (b *TokenBucket) Allow() bool {
\tb.mu.Lock()
\tdefer b.mu.Unlock()
\tb.refill()
\tif b.tokens >= 1 {
\t\tb.tokens--
\t\treturn true
\t}
\treturn false
}

func (b *TokenBucket) refill() {
\tnow := time.Now()
\telapsed := now.Sub(b.lastRefill).Seconds()
\tb.tokens += elapsed * b.refillRate
\tif b.tokens > b.max {
\t\tb.tokens = b.max
\t}
\tb.lastRefill = now
}
""",
    },
    {
        "id": "go_ext_json_marshal",
        "language": "go",
        "notes": "Custom JSON marshaling with proper error handling",
        "code": """\
package models

import (
\t"encoding/json"
\t"fmt"
\t"time"
)

type Event struct {
\tID        string    `json:"id"`
\tType      string    `json:"type"`
\tPayload   json.RawMessage `json:"payload"`
\tCreatedAt time.Time `json:"created_at"`
}

type Timestamp struct {
\ttime.Time
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
\treturn json.Marshal(t.Time.Unix())
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
\tvar unix int64
\tif err := json.Unmarshal(data, &unix); err != nil {
\t\treturn fmt.Errorf("timestamp must be a unix epoch: %w", err)
\t}
\tt.Time = time.Unix(unix, 0)
\treturn nil
}

func ParseEvent(data []byte) (*Event, error) {
\tvar e Event
\tif err := json.Unmarshal(data, &e); err != nil {
\t\treturn nil, fmt.Errorf("invalid event JSON: %w", err)
\t}
\tif e.ID == "" || e.Type == "" {
\t\treturn nil, fmt.Errorf("event must have id and type")
\t}
\treturn &e, nil
}
""",
    },
    {
        "id": "go_ext_filepath_safe",
        "language": "go",
        "notes": "Safe filepath handling with traversal prevention",
        "code": """\
package fileutil

import (
\t"fmt"
\t"os"
\t"path/filepath"
\t"strings"
)

func SafeJoin(baseDir, userPath string) (string, error) {
\tcleaned := filepath.Clean(userPath)
\tif filepath.IsAbs(cleaned) {
\t\treturn "", fmt.Errorf("absolute paths not allowed")
\t}
\tif strings.Contains(cleaned, "..") {
\t\treturn "", fmt.Errorf("path traversal not allowed")
\t}
\tfull := filepath.Join(baseDir, cleaned)
\tresolved, err := filepath.Abs(full)
\tif err != nil {
\t\treturn "", err
\t}
\tbase, err := filepath.Abs(baseDir)
\tif err != nil {
\t\treturn "", err
\t}
\tif !strings.HasPrefix(resolved, base+string(os.PathSeparator)) && resolved != base {
\t\treturn "", fmt.Errorf("path escapes base directory")
\t}
\treturn resolved, nil
}

func ReadFileSafe(baseDir, name string) ([]byte, error) {
\tpath, err := SafeJoin(baseDir, name)
\tif err != nil {
\t\treturn nil, err
\t}
\treturn os.ReadFile(path)
}
""",
    },

    # ─────────────────────── ADDITIONAL RUST (3 samples) ──────────────────────
    {
        "id": "rust_ext_state_machine",
        "language": "rust",
        "notes": "Type-state pattern for compile-time state machine",
        "code": """\
pub struct Draft;
pub struct Published;
pub struct Archived;

pub struct Article<State> {
    title: String,
    content: String,
    _state: std::marker::PhantomData<State>,
}

impl Article<Draft> {
    pub fn new(title: String, content: String) -> Self {
        Self {
            title,
            content,
            _state: std::marker::PhantomData,
        }
    }

    pub fn edit(&mut self, content: String) {
        self.content = content;
    }

    pub fn publish(self) -> Article<Published> {
        Article {
            title: self.title,
            content: self.content,
            _state: std::marker::PhantomData,
        }
    }
}

impl Article<Published> {
    pub fn archive(self) -> Article<Archived> {
        Article {
            title: self.title,
            content: self.content,
            _state: std::marker::PhantomData,
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }
}
""",
    },
    {
        "id": "rust_ext_serde_custom",
        "language": "rust",
        "notes": "Custom serde deserializer for validated types",
        "code": """\
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Email(String);

impl Email {
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.contains('@') && s.len() >= 3 {
            Ok(Self(s.to_lowercase()))
        } else {
            Err(format!("invalid email: {}", s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Email::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserInput {
    pub name: String,
    pub email: Email,
    #[serde(default)]
    pub active: bool,
}
""",
    },
    {
        "id": "rust_ext_tracing_spans",
        "language": "rust",
        "notes": "Structured logging with tracing spans",
        "code": """\
use tracing::{info, instrument, warn};

#[instrument(skip(password))]
pub fn authenticate(username: &str, password: &str) -> Result<String, &'static str> {
    info!("authentication attempt");
    if username.is_empty() || password.is_empty() {
        warn!("empty credentials provided");
        return Err("credentials required");
    }
    // in production, verify against database
    Ok(format!("token-for-{}", username))
}

#[instrument]
pub async fn process_order(order_id: u64, items: &[String]) -> Result<String, &'static str> {
    info!(item_count = items.len(), "processing order");
    if items.is_empty() {
        return Err("order must have at least one item");
    }
    Ok(format!("order-{}-confirmed", order_id))
}
""",
    },

    # ─────────────────────── ADDITIONAL JAVA (2 samples) ──────────────────────
    {
        "id": "java_ext_stream_collectors",
        "language": "java",
        "notes": "Stream API with custom collectors",
        "code": """\
import java.util.*;
import java.util.stream.*;

public class StreamUtils {

    public record Employee(String name, String department, double salary) {}

    public static Map<String, Double> averageSalaryByDept(List<Employee> employees) {
        return employees.stream()
            .collect(Collectors.groupingBy(
                Employee::department,
                Collectors.averagingDouble(Employee::salary)
            ));
    }

    public static Map<String, Optional<Employee>> highestPaidByDept(List<Employee> employees) {
        return employees.stream()
            .collect(Collectors.groupingBy(
                Employee::department,
                Collectors.maxBy(Comparator.comparingDouble(Employee::salary))
            ));
    }

    public static String joinNames(List<Employee> employees, String delimiter) {
        return employees.stream()
            .map(Employee::name)
            .sorted()
            .collect(Collectors.joining(delimiter));
    }

    public static DoubleSummaryStatistics salaryStats(List<Employee> employees) {
        return employees.stream()
            .mapToDouble(Employee::salary)
            .summaryStatistics();
    }
}
""",
    },
    {
        "id": "java_ext_virtual_threads",
        "language": "java",
        "notes": "Virtual threads for concurrent operations",
        "code": """\
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class ConcurrentFetcher {

    public record FetchResult(String url, String body, long durationMs) {}

    public List<FetchResult> fetchAll(List<String> urls, long timeoutSeconds)
            throws InterruptedException {
        List<FetchResult> results = new ArrayList<>();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<FetchResult>> futures = urls.stream()
                .map(url -> executor.submit(() -> fetchOne(url)))
                .toList();

            for (Future<FetchResult> future : futures) {
                try {
                    results.add(future.get(timeoutSeconds, TimeUnit.SECONDS));
                } catch (TimeoutException e) {
                    future.cancel(true);
                } catch (ExecutionException e) {
                    // skip failed fetches
                }
            }
        }
        return results;
    }

    private FetchResult fetchOne(String url) {
        long start = System.currentTimeMillis();
        // simulate network call
        String body = "response from " + url;
        long duration = System.currentTimeMillis() - start;
        return new FetchResult(url, body, duration);
    }
}
""",
    },
]
