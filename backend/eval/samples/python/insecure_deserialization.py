"""Intentionally vulnerable: insecure deserialization patterns. For eval only."""
import pickle
import base64
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load_session", methods=["POST"])
def load_session():
    session_data = request.cookies.get("session_data")
    raw = base64.b64decode(session_data)
    # UNSAFE: pickle.loads on attacker-controlled bytes allows RCE
    user = pickle.loads(raw)
    return f"Welcome back, {user['name']}"


@app.route("/import_config", methods=["POST"])
def import_config():
    config_data = request.data
    # UNSAFE: yaml.load without SafeLoader allows arbitrary object construction
    config = yaml.load(config_data, Loader=yaml.Loader)
    return str(config.get("setting"))
