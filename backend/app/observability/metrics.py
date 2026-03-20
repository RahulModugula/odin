from prometheus_client import Counter, Gauge, Histogram, generate_latest
from starlette.requests import Request
from starlette.responses import Response

reviews_total = Counter(
    "reviews_total",
    "Total number of code reviews",
    ["language", "cache_status"],
)

agent_errors_total = Counter(
    "agent_errors_total",
    "Total number of agent errors",
    ["agent_name"],
)

review_duration_seconds = Histogram(
    "review_duration_seconds",
    "Duration of code reviews in seconds",
)

agent_duration_seconds = Histogram(
    "agent_duration_seconds",
    "Duration of individual agent runs in seconds",
    ["agent_name"],
)

reviews_in_progress = Gauge(
    "reviews_in_progress",
    "Number of reviews currently in progress",
)


async def metrics_endpoint(request: Request) -> Response:
    """Expose Prometheus metrics at GET /metrics."""
    body = generate_latest()
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
