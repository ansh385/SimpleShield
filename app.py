from flask import Flask, render_template, request
import requests
import ssl
import socket
from datetime import datetime

app = Flask(__name__)


def get_ssl_expiry(hostname):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(
            cert["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )

        days_left = (expiry_date - datetime.utcnow()).days

        return expiry_date.strftime("%d %B %Y"), days_left

    except:
        return "Not Found", -1


def detect_technology(response):

    tech = []

    headers = str(response.headers).lower()
    html = response.text.lower()

    if "cloudflare" in headers:
        tech.append("Cloudflare")

    if "wp-content" in html:
        tech.append("WordPress")

    if "shopify" in html:
        tech.append("Shopify")

    if "react" in html:
        tech.append("React")

    if "bootstrap" in html:
        tech.append("Bootstrap")

    if "jquery" in html:
        tech.append("jQuery")

    return tech


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    website = request.form.get("website")

    try:

        if not website.startswith(("http://", "https://")):
            website = "https://" + website

        response = requests.get(
            website,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        headers = response.headers

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
        }

        score = 0

        for value in security_headers.values():
            if value:
                score += 25

        if score <= 25:
            risk = "🔴 High Risk"
        elif score <= 75:
            risk = "🟡 Medium Risk"
        else:
            risk = "🟢 Low Risk"

        hostname = website.replace("https://", "")
        hostname = hostname.replace("http://", "")
        hostname = hostname.split("/")[0]

        ssl_expiry, days_left = get_ssl_expiry(hostname)

        technologies = detect_technology(response)

        return render_template(
            "result.html",
            website=website,
            security_headers=security_headers,
            score=score,
            risk=risk,
            ssl_expiry=ssl_expiry,
            days_left=days_left,
            technologies=technologies
        )

    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    app.run(debug=True)