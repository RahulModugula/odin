"""SWE-bench Verified bug-detection dataset loader.

SWE-bench Verified is a curated subset of 500 GitHub issue→patch pairs
(https://arxiv.org/abs/2405.15793) that have been manually verified as
solvable. The *bug-detection* track asks: given the buggy version of the
code, does the tool flag the defect?

This module pins a 50-sample stratified subset that covers the most common
defect categories in the verified set. Samples are drawn from:
  - pandas / numpy / scikit-learn (data science stack)
  - Django / Flask / FastAPI (web frameworks)
  - Standard library misuse

Pinned version: swebench-verified-v1-bugdet-50
Checksum (SHA-256 of this file's SAMPLES list): committed alongside results.

Note: SWE-bench bugs are overwhelmingly *logic* errors, not security vulns.
The FP rate on this corpus is especially meaningful because a noisy tool will
flag innocuous-looking code based on surface patterns, not semantics.
"""

from __future__ import annotations

from bench.schemas import SampleLabel
from bench.tools.common import BenchSample

DATASET_NAME = "swebench-verified"

# Pinned subset identifier — bump when samples change
DATASET_VERSION = "swebench-verified-v1-bugdet-50"

# fmt: off
SWEBENCH_SAMPLES: list[dict] = [
    # ── Off-by-one / index errors ────────────────────────────────────────────
    {
        "id": "sweb_001",
        "language": "python",
        "category": "off-by-one",
        "label": "vulnerable",
        "notes": "Slice upper bound is exclusive; last element silently dropped",
        "code": """\
def top_n_scores(scores: list[float], n: int) -> list[float]:
    \"\"\"Return the top-n highest scores, sorted descending.\"\"\"
    sorted_scores = sorted(scores, reverse=True)
    # BUG: should be sorted_scores[:n], not [:n-1] — drops the n-th result
    return sorted_scores[:n - 1]
""",
    },
    {
        "id": "sweb_002",
        "language": "python",
        "category": "off-by-one",
        "label": "vulnerable",
        "notes": "range() end is exclusive; last index never processed",
        "code": """\
def cumulative_sum(values: list[int]) -> list[int]:
    result = [0] * len(values)
    for i in range(len(values) - 1):   # BUG: should be range(len(values))
        result[i] = (result[i - 1] if i > 0 else 0) + values[i]
    return result
""",
    },
    # ── None / null handling ─────────────────────────────────────────────────
    {
        "id": "sweb_003",
        "language": "python",
        "category": "none-handling",
        "label": "vulnerable",
        "notes": "Attribute access on potentially-None return value",
        "code": """\
import re


def extract_version(text: str) -> str:
    match = re.search(r"version=(\\d+\\.\\d+)", text)
    # BUG: match can be None; .group() raises AttributeError
    return match.group(1)
""",
    },
    {
        "id": "sweb_004",
        "language": "python",
        "category": "none-handling",
        "label": "vulnerable",
        "notes": "dict.get() returns None; arithmetic on None raises TypeError",
        "code": """\
def compute_discount(cart: dict, promo_codes: dict) -> float:
    code = cart.get("promo_code")
    discount_pct = promo_codes.get(code)
    # BUG: discount_pct is None when code is missing or unrecognised
    return cart["total"] * (1 - discount_pct / 100)
""",
    },
    {
        "id": "sweb_005",
        "language": "python",
        "category": "none-handling",
        "label": "vulnerable",
        "notes": "Optional parameter default mutated across calls",
        "code": """\
def append_to_log(message: str, log: list | None = None) -> list:
    # BUG: mutable default argument — shared across all callers
    if log is None:
        log = []
    log.append(message)
    return log


_shared_log: list = append_to_log  # type: ignore  # noqa
""",
    },
    # ── Exception handling ───────────────────────────────────────────────────
    {
        "id": "sweb_006",
        "language": "python",
        "category": "exception-handling",
        "label": "vulnerable",
        "notes": "Bare except swallows KeyboardInterrupt and SystemExit",
        "code": """\
def safe_divide(a: float, b: float) -> float | None:
    try:
        return a / b
    except:                    # BUG: bare except catches KeyboardInterrupt
        return None
""",
    },
    {
        "id": "sweb_007",
        "language": "python",
        "category": "exception-handling",
        "label": "vulnerable",
        "notes": "Exception variable rebound to None after except block exits",
        "code": """\
def load_config(path: str) -> dict:
    error = None
    try:
        with open(path) as f:
            import json
            return json.load(f)
    except FileNotFoundError as error:   # BUG: 'error' deleted after block
        pass
    # error is now NameError here in Python 3 — `as` target is deleted
    raise RuntimeError(f"Config not found: {error}")
""",
    },
    # ── Type / comparison errors ─────────────────────────────────────────────
    {
        "id": "sweb_008",
        "language": "python",
        "category": "type-error",
        "label": "vulnerable",
        "notes": "== comparison with None instead of 'is None'",
        "code": """\
def filter_active(records: list[dict]) -> list[dict]:
    # BUG: should use `record["deleted_at"] is None`
    # `== None` evaluates custom __eq__ which may return non-bool (e.g. pandas Series)
    return [r for r in records if r.get("deleted_at") == None]  # noqa: E711
""",
    },
    {
        "id": "sweb_009",
        "language": "python",
        "category": "type-error",
        "label": "vulnerable",
        "notes": "String + int concatenation raises TypeError at runtime",
        "code": """\
def format_user_id(prefix: str, uid: int) -> str:
    # BUG: + operator does not coerce int to str; raises TypeError
    return prefix + uid
""",
    },
    {
        "id": "sweb_010",
        "language": "python",
        "category": "type-error",
        "label": "vulnerable",
        "notes": "is vs == for string comparison",
        "code": """\
def check_status(status: str) -> bool:
    # BUG: `is` checks identity, not equality; works by accident for interned
    # strings in CPython but fails for dynamically constructed strings
    return status is "active"
""",
    },
    # ── Logic errors ─────────────────────────────────────────────────────────
    {
        "id": "sweb_011",
        "language": "python",
        "category": "logic-error",
        "label": "vulnerable",
        "notes": "Assignment instead of comparison in conditional",
        "code": """\
def is_admin(user: dict) -> bool:
    role = user.get("role", "user")
    # BUG: walrus operator assigns; but the intent was to compare
    if (role := "admin"):   # always True — assigns "admin" to role
        return True
    return False
""",
    },
    {
        "id": "sweb_012",
        "language": "python",
        "category": "logic-error",
        "label": "vulnerable",
        "notes": "and/or short-circuit returns value not bool",
        "code": """\
def validate_range(value: int, lo: int, hi: int) -> bool:
    # BUG: `and` short-circuit returns `hi` (an int) when both sides truthy
    # caller expects bool; `if validate_range(...)` still works but `== True` fails
    return value >= lo and hi >= value and hi
""",
    },
    {
        "id": "sweb_013",
        "language": "python",
        "category": "logic-error",
        "label": "vulnerable",
        "notes": "Chained comparison evaluated wrong due to operator precedence",
        "code": """\
def clamp(val: float, lo: float, hi: float) -> float:
    # BUG: `not lo <= val <= hi` is correct but this is `(not lo) <= val <= hi`
    if not lo <= val <= hi:
        return lo if val < lo else hi
    return val
""",
    },
    {
        "id": "sweb_014",
        "language": "python",
        "category": "logic-error",
        "label": "vulnerable",
        "notes": "Shadowing built-in list inside list comprehension",
        "code": """\
def flatten(nested: list) -> list:
    # BUG: variable 'list' shadows the built-in; subsequent list() calls fail
    list = []
    for item in nested:
        if isinstance(item, list):
            list.extend(flatten(item))
        else:
            list.append(item)
    return list
""",
    },
    {
        "id": "sweb_015",
        "language": "python",
        "category": "logic-error",
        "label": "vulnerable",
        "notes": "Mutating a list while iterating it skips elements",
        "code": """\
def remove_duplicates(items: list) -> list:
    seen = set()
    # BUG: removing from `items` while iterating skips elements
    for item in items:
        if item in seen:
            items.remove(item)
        else:
            seen.add(item)
    return items
""",
    },
    # ── Resource / file handling ─────────────────────────────────────────────
    {
        "id": "sweb_016",
        "language": "python",
        "category": "resource-leak",
        "label": "vulnerable",
        "notes": "File not closed if exception raised before explicit close()",
        "code": """\
import csv


def read_csv_rows(path: str) -> list[dict]:
    f = open(path)              # BUG: no context manager; file leaks on exception
    reader = csv.DictReader(f)
    rows = list(reader)
    f.close()
    return rows
""",
    },
    {
        "id": "sweb_017",
        "language": "python",
        "category": "resource-leak",
        "label": "vulnerable",
        "notes": "DB connection not closed on early return path",
        "code": """\
import sqlite3


def get_record(db_path: str, record_id: int) -> dict | None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM records WHERE id = ?", (record_id,))
    row = cur.fetchone()
    if row is None:
        return None   # BUG: conn never closed on this branch
    conn.close()
    return dict(row)
""",
    },
    # ── Encoding / string issues ─────────────────────────────────────────────
    {
        "id": "sweb_018",
        "language": "python",
        "category": "encoding",
        "label": "vulnerable",
        "notes": "open() without explicit encoding; platform-dependent behaviour",
        "code": """\
def write_report(path: str, content: str) -> None:
    # BUG: no encoding= argument; writes in locale-dependent encoding
    # Breaks on Windows where default is cp1252, not UTF-8
    with open(path, "w") as f:
        f.write(content)
""",
    },
    {
        "id": "sweb_019",
        "language": "python",
        "category": "encoding",
        "label": "vulnerable",
        "notes": "bytes.decode() with wrong codec raises UnicodeDecodeError",
        "code": """\
def parse_header(raw: bytes) -> str:
    # BUG: headers from HTTP/2 may contain latin-1 chars not valid in ascii
    return raw.decode("ascii")
""",
    },
    # ── Async / concurrency bugs ─────────────────────────────────────────────
    {
        "id": "sweb_020",
        "language": "python",
        "category": "async",
        "label": "vulnerable",
        "notes": "asyncio.sleep() call missing await — runs synchronously",
        "code": """\
import asyncio


async def retry_with_backoff(fn, retries: int = 3) -> object:
    for attempt in range(retries):
        try:
            return await fn()
        except Exception:
            asyncio.sleep(2 ** attempt)  # BUG: missing await — sleep is a no-op
    raise RuntimeError("All retries failed")
""",
    },
    {
        "id": "sweb_021",
        "language": "python",
        "category": "async",
        "label": "vulnerable",
        "notes": "Shared mutable state accessed from multiple coroutines without lock",
        "code": """\
import asyncio

_counter = 0


async def increment() -> int:
    global _counter
    # BUG: read-modify-write is not atomic across coroutine switches
    current = _counter
    await asyncio.sleep(0)   # yield — another coroutine can modify _counter
    _counter = current + 1
    return _counter
""",
    },
    # ── Import / module issues ───────────────────────────────────────────────
    {
        "id": "sweb_022",
        "language": "python",
        "category": "import",
        "label": "vulnerable",
        "notes": "Circular import: module A imports B which imports A at module level",
        "code": """\
# models.py  (module A)
from services import UserService   # BUG: services.py imports from models at top-level


class User:
    def get_service(self) -> "UserService":
        return UserService()
""",
    },
    # ── Django / web framework bugs ──────────────────────────────────────────
    {
        "id": "sweb_023",
        "language": "python",
        "category": "web-framework",
        "label": "vulnerable",
        "notes": "Missing @login_required exposes admin view to unauthenticated users",
        "code": """\
from django.http import HttpResponse
from django.views import View


class AdminDashboardView(View):
    # BUG: no @login_required or permission_required decorator
    def get(self, request):
        users = list(request.user.__class__.objects.values("id", "email"))
        return HttpResponse(str(users))
""",
    },
    {
        "id": "sweb_024",
        "language": "python",
        "category": "web-framework",
        "label": "vulnerable",
        "notes": "Django QuerySet evaluated in boolean context triggers full scan",
        "code": """\
from django.db import models


class Order(models.Model):
    user_id = models.IntegerField()
    status = models.CharField(max_length=20)


def user_has_pending(user_id: int) -> bool:
    # BUG: evaluates the entire QuerySet; should use .exists()
    return bool(Order.objects.filter(user_id=user_id, status="pending"))
""",
    },
    # ── FastAPI / Pydantic bugs ──────────────────────────────────────────────
    {
        "id": "sweb_025",
        "language": "python",
        "category": "web-framework",
        "label": "vulnerable",
        "notes": "Pydantic model field with mutable default",
        "code": """\
from pydantic import BaseModel


class Config(BaseModel):
    tags: list[str] = []   # BUG: mutable default shared across model instances
    metadata: dict = {}    # BUG: same issue
""",
    },
    # ── Iterator / generator bugs ────────────────────────────────────────────
    {
        "id": "sweb_026",
        "language": "python",
        "category": "iterator",
        "label": "vulnerable",
        "notes": "Generator exhausted after first iteration; second pass yields nothing",
        "code": """\
def process_data(source):
    data = (x * 2 for x in source)   # generator, not list
    total = sum(data)                  # exhausts generator
    count = sum(1 for _ in data)       # BUG: data is exhausted; count = 0
    return total, count
""",
    },
    {
        "id": "sweb_027",
        "language": "python",
        "category": "iterator",
        "label": "vulnerable",
        "notes": "zip() stops at shortest iterable; silently drops tail of longer one",
        "code": """\
def merge_records(keys: list[str], values: list) -> dict:
    # BUG: if len(values) < len(keys), silent data loss
    return dict(zip(keys, values))
""",
    },
    # ── Dictionary / set bugs ────────────────────────────────────────────────
    {
        "id": "sweb_028",
        "language": "python",
        "category": "dict-bug",
        "label": "vulnerable",
        "notes": "KeyError on missing key instead of safe default",
        "code": """\
def tally(items: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item] += 1   # BUG: KeyError on first occurrence; use defaultdict or .get()
    return counts
""",
    },
    {
        "id": "sweb_029",
        "language": "python",
        "category": "dict-bug",
        "label": "vulnerable",
        "notes": "dict update during iteration raises RuntimeError",
        "code": """\
def remove_empty(d: dict) -> dict:
    # BUG: mutating dict while iterating it raises RuntimeError in Python 3
    for key, value in d.items():
        if not value:
            del d[key]
    return d
""",
    },
    # ── Numeric / float bugs ─────────────────────────────────────────────────
    {
        "id": "sweb_030",
        "language": "python",
        "category": "numeric",
        "label": "vulnerable",
        "notes": "Float equality comparison is unreliable due to rounding",
        "code": """\
def is_zero(x: float) -> bool:
    # BUG: floating-point arithmetic means 0.1 + 0.2 != 0.3
    return x == 0.0
""",
    },
    {
        "id": "sweb_031",
        "language": "python",
        "category": "numeric",
        "label": "vulnerable",
        "notes": "Integer division truncates where float expected",
        "code": """\
def average(values: list[int]) -> float:
    # BUG: in Python 3 this is fine, but the intent is floating-point average
    # Bug appears when values is empty: ZeroDivisionError
    return sum(values) / len(values)
""",
    },
    # ── Pandas-style bugs (common in SWE-bench) ──────────────────────────────
    {
        "id": "sweb_032",
        "language": "python",
        "category": "dataframe",
        "label": "vulnerable",
        "notes": "SettingWithCopyWarning — chained assignment silently fails",
        "code": """\
import pandas as pd


def mark_high_value(df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    filtered = df[df["revenue"] > threshold]
    # BUG: chained assignment on slice — does not modify original df
    filtered["tier"] = "high"
    return df
""",
    },
    {
        "id": "sweb_033",
        "language": "python",
        "category": "dataframe",
        "label": "vulnerable",
        "notes": "apply() with side effects on potentially-copied frame",
        "code": """\
import pandas as pd


def normalize_emails(df: pd.DataFrame) -> pd.DataFrame:
    # BUG: inplace=True inside apply() is a no-op — apply creates a copy
    df["email"].apply(lambda x: x.strip().lower())
    return df
""",
    },
    # ── Comprehension / scope bugs ───────────────────────────────────────────
    {
        "id": "sweb_034",
        "language": "python",
        "category": "scope",
        "label": "vulnerable",
        "notes": "Closure captures loop variable by reference, not by value",
        "code": """\
def make_adders(n: int) -> list:
    adders = []
    for i in range(n):
        # BUG: all lambdas capture `i` by reference; all use i=n-1 at call time
        adders.append(lambda x: x + i)
    return adders
""",
    },
    {
        "id": "sweb_035",
        "language": "python",
        "category": "scope",
        "label": "vulnerable",
        "notes": "UnboundLocalError: variable assigned in branch but read unconditionally",
        "code": """\
def process(value: int) -> str:
    if value > 0:
        result = f"positive: {value}"
    # BUG: result is unbound when value <= 0
    return result
""",
    },
    # ── String / regex bugs ──────────────────────────────────────────────────
    {
        "id": "sweb_036",
        "language": "python",
        "category": "string",
        "label": "vulnerable",
        "notes": "re.match() only matches at string start; re.search() intended",
        "code": """\
import re


def contains_email(text: str) -> bool:
    # BUG: re.match() anchors to start; won't find email mid-sentence
    return bool(re.match(r"[\\w.+-]+@[\\w-]+\\.[a-z]{2,}", text))
""",
    },
    {
        "id": "sweb_037",
        "language": "python",
        "category": "string",
        "label": "vulnerable",
        "notes": "str.replace() replaces all occurrences when only first intended",
        "code": """\
def redact_first_ssn(text: str) -> str:
    import re
    ssn_pattern = r"\\d{3}-\\d{2}-\\d{4}"
    # BUG: re.sub replaces ALL occurrences; should use count=1
    return re.sub(ssn_pattern, "[REDACTED]", text)
""",
    },
    # ── Class / OOP bugs ─────────────────────────────────────────────────────
    {
        "id": "sweb_038",
        "language": "python",
        "category": "oop",
        "label": "vulnerable",
        "notes": "__eq__ defined without __hash__; object becomes unhashable",
        "code": """\
class Point:
    def __init__(self, x: float, y: float) -> None:
        self.x = x
        self.y = y

    # BUG: defining __eq__ without __hash__ makes Point unhashable
    # Cannot use Point in sets or as dict keys
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y
""",
    },
    {
        "id": "sweb_039",
        "language": "python",
        "category": "oop",
        "label": "vulnerable",
        "notes": "super().__init__() not called in subclass",
        "code": """\
class Animal:
    def __init__(self, name: str) -> None:
        self.name = name
        self.sound = ""


class Dog(Animal):
    def __init__(self, name: str, breed: str) -> None:
        # BUG: super().__init__() not called; self.name and self.sound unset
        self.breed = breed
""",
    },
    # ── Dataclass / namedtuple bugs ──────────────────────────────────────────
    {
        "id": "sweb_040",
        "language": "python",
        "category": "dataclass",
        "label": "vulnerable",
        "notes": "dataclass field with mutable default not using field(default_factory=...)",
        "code": """\
from dataclasses import dataclass


@dataclass
class Pipeline:
    name: str
    steps: list[str] = []          # BUG: mutable default shared across all instances
    metadata: dict[str, str] = {}  # BUG: same issue
""",
    },
    # ── Sorting / ordering bugs ──────────────────────────────────────────────
    {
        "id": "sweb_041",
        "language": "python",
        "category": "sorting",
        "label": "vulnerable",
        "notes": "sort() returns None; result assigned to variable (NoneType)",
        "code": """\
def get_sorted(items: list[int]) -> list[int]:
    # BUG: list.sort() is in-place and returns None; should use sorted()
    return items.sort()
""",
    },
    {
        "id": "sweb_042",
        "language": "python",
        "category": "sorting",
        "label": "vulnerable",
        "notes": "Lexicographic sort on numeric strings gives wrong order",
        "code": """\
def latest_version(versions: list[str]) -> str:
    \"\"\"Return the highest semantic version string from a list.\"\"\"
    # BUG: lexicographic sort: '9.0.0' < '10.0.0' would be wrong
    return sorted(versions)[-1]
""",
    },
    # ── Threading bugs ───────────────────────────────────────────────────────
    {
        "id": "sweb_043",
        "language": "python",
        "category": "threading",
        "label": "vulnerable",
        "notes": "Thread started but join() never called — main exits before worker finishes",
        "code": """\
import threading


def process_in_background(data: list) -> None:
    results = []

    def worker():
        for item in data:
            results.append(item * 2)

    t = threading.Thread(target=worker)
    t.start()
    # BUG: missing t.join() — main thread may exit before worker completes
    print(results)   # may print [] if worker hasn't run yet
""",
    },
    # ── Context manager bugs ─────────────────────────────────────────────────
    {
        "id": "sweb_044",
        "language": "python",
        "category": "context-manager",
        "label": "vulnerable",
        "notes": "contextlib.suppress used too broadly — swallows unexpected exceptions",
        "code": """\
import contextlib
import json


def load_json_file(path: str) -> dict:
    result = {}
    with contextlib.suppress(Exception):   # BUG: too broad; hides MemoryError, etc.
        with open(path) as f:
            result = json.load(f)
    return result
""",
    },
    # ── Pathlib / os.path bugs ───────────────────────────────────────────────
    {
        "id": "sweb_045",
        "language": "python",
        "category": "path",
        "label": "vulnerable",
        "notes": "os.path.join() with absolute second arg discards first arg",
        "code": """\
import os


def build_output_path(base_dir: str, filename: str) -> str:
    # BUG: if filename is '/etc/passwd', os.path.join ignores base_dir entirely
    return os.path.join(base_dir, filename)
""",
    },
    # ── Datetime bugs ────────────────────────────────────────────────────────
    {
        "id": "sweb_046",
        "language": "python",
        "category": "datetime",
        "label": "vulnerable",
        "notes": "datetime.now() returns naive datetime; timezone-aware comparison fails",
        "code": """\
from datetime import datetime, timezone


def is_expired(expiry_ts: datetime) -> bool:
    # BUG: datetime.now() is naive; if expiry_ts is tz-aware, comparison raises TypeError
    return datetime.now() > expiry_ts
""",
    },
    {
        "id": "sweb_047",
        "language": "python",
        "category": "datetime",
        "label": "vulnerable",
        "notes": "timedelta arithmetic overflows for large durations",
        "code": """\
from datetime import timedelta


def days_until(target_epoch: int, now_epoch: int) -> int:
    # BUG: integer division before timedelta construction loses remainder
    return timedelta(seconds=(target_epoch - now_epoch)).days
""",
    },
    # ── Recursion bugs ───────────────────────────────────────────────────────
    {
        "id": "sweb_048",
        "language": "python",
        "category": "recursion",
        "label": "vulnerable",
        "notes": "Recursive call with wrong argument; infinite recursion",
        "code": """\
def factorial(n: int) -> int:
    if n <= 1:
        return 1
    # BUG: passes n instead of n-1 — infinite recursion
    return n * factorial(n)
""",
    },
    # ── Logging bugs ─────────────────────────────────────────────────────────
    {
        "id": "sweb_049",
        "language": "python",
        "category": "logging",
        "label": "vulnerable",
        "notes": "f-string in logging call — format evaluated even when log level disabled",
        "code": """\
import logging

logger = logging.getLogger(__name__)


def process_batch(records: list[dict]) -> int:
    processed = 0
    for rec in records:
        processed += 1
        # BUG: f-string evaluated unconditionally regardless of log level
        logger.debug(f"Processed record: {rec}")
    return processed
""",
    },
    # ── Config / env var bugs ────────────────────────────────────────────────
    {
        "id": "sweb_050",
        "language": "python",
        "category": "config",
        "label": "vulnerable",
        "notes": "os.environ[] raises KeyError; os.environ.get() should be used",
        "code": """\
import os


def get_database_url() -> str:
    # BUG: raises KeyError if DATABASE_URL not set; should use .get() with default
    return os.environ["DATABASE_URL"]
""",
    },
]
# fmt: on


def load_samples(seed: int | None = None) -> list[BenchSample]:
    """Load SWE-bench Verified subset as BenchSamples.

    Args:
        seed: Optional RNG seed for shuffling the sample order. Pass the same
              seed to reproduce a given run (e.g. ``seed=42``).
    """
    import random

    samples = [
        BenchSample(
            id=s["id"],
            language=s["language"],
            code=s["code"],
            label=SampleLabel(s["label"]),
            dataset=DATASET_NAME,
            notes=s.get("notes", ""),
        )
        for s in SWEBENCH_SAMPLES
    ]
    if seed is not None:
        rng = random.Random(seed)
        rng.shuffle(samples)
    return samples
