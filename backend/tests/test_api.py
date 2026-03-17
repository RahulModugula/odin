from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "python" in data["supported_languages"]


def test_review_valid_python(client: TestClient, python_good_code: str) -> None:
    response = client.post("/api/review", json={
        "code": python_good_code,
        "language": "python",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "python"
    assert data["metrics"]["num_functions"] == 5  # 2 top-level + 3 methods
    assert data["metrics"]["num_classes"] == 1
    assert data["overall_score"] == 100


def test_review_empty_code(client: TestClient) -> None:
    response = client.post("/api/review", json={
        "code": "",
        "language": "python",
    })
    assert response.status_code == 422


def test_review_javascript(client: TestClient, javascript_bad_code: str) -> None:
    response = client.post("/api/review", json={
        "code": javascript_bad_code,
        "language": "javascript",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["metrics"]["num_functions"] >= 2


def test_review_includes_timing(client: TestClient, python_good_code: str) -> None:
    response = client.post("/api/review", json={
        "code": python_good_code,
        "language": "python",
    })
    data = response.json()
    assert data["total_time_ms"] > 0
    assert "id" in data
