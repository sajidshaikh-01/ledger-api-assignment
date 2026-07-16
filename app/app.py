import os
import hashlib
import ipaddress
import socket
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

LEDGER = [
    {
        "id": "txn_1001",
        "pan": "4242424242424242",
        "amount": 4200,
        "currency": "USD",
        "status": "captured",
    },
    {
        "id": "txn_1002",
        "pan": "5555555555554444",
        "amount": 1899,
        "currency": "EUR",
        "status": "refunded",
    },
]

# Demo allowlist for outbound requests
# Replace with your trusted partner domains in production.
ALLOWED_FETCH_HOSTS = {
    "httpbin.org",
    "example.com",
}


def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    if parsed.hostname not in ALLOWED_FETCH_HOSTS:
        return False

    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(resolved_ip).is_private:
            return False
    except Exception:
        return False

    return True


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/tokenize", methods=["POST"])
def tokenize():
    payload = request.get_json(silent=True) or {}
    pan = payload.get("pan", "")
    token = "tok_" + hashlib.sha256(pan.encode()).hexdigest()[:24]
    return jsonify(token=token, last4=pan[-4:])


@app.route("/transactions")
def transactions():
    return jsonify(transactions=LEDGER)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return jsonify(loaded=str(config))


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")

    if not is_safe_url(url):
        return jsonify(error="URL not permitted"), 400

    resp = requests.get(url, timeout=5)

    return jsonify(
        status_code=resp.status_code,
        body=resp.text[:2048],
    )


if __name__ == "__main__":
    # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    # Running on 0.0.0.0 is required inside a container so the application
    # is reachable through the Kubernetes Service/Ingress.
    app.run(host="0.0.0.0", port=8080)