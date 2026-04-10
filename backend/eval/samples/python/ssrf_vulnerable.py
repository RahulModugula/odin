"""Intentionally vulnerable: Server-Side Request Forgery. For eval only."""
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    # User controls the full URL — attacker can reach 169.254.169.254
    target_url = request.args.get("url")
    try:
        resp = requests.get(target_url, timeout=5)
        return jsonify({"status": resp.status_code, "body": resp.text[:500]})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/preview", methods=["POST"])
def preview_link():
    link = request.json.get("link")
    # No scheme check, no allowlist, no private-range blocking
    data = requests.post(link, json={"source": "odin"}).content
    return data
