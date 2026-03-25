"""Intentionally vulnerable: OS command injection patterns. For eval only."""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "8.8.8.8")
    # UNSAFE: shell=True with f-string — semicolons inject commands
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


@app.route("/convert", methods=["POST"])
def convert_image():
    filename = request.form.get("filename", "input.jpg")
    output = request.form.get("output", "out.png")
    # UNSAFE: os.system with f-string interpolation
    os.system(f"convert {filename} {output}")
    return "converted"
