"""
SafeURL — URL Safety Checker
Owner: Aditi Kumari

A small Flask web application that checks a URL string for common warning signs.
It does not visit, open, or crawl the submitted website. Results are heuristic
indicators, not a guarantee that a URL is safe or malicious.
"""

from urllib.parse import urlparse
import ipaddress
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeURL | URL Safety Checker</title>
  <style>
    :root { --navy:#0b1224; --panel:#131e35; --line:#263652; --text:#edf4ff;
            --muted:#a8b8d3; --green:#35d49a; --orange:#ffb454; --red:#ff6678; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:system-ui,-apple-system,Segoe UI,sans-serif;
      color:var(--text); background:radial-gradient(circle at top,#1b3156,var(--navy) 55%);
      min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
    .wrap { width:min(820px,100%); }
    .brand { display:flex; align-items:center; gap:12px; margin-bottom:20px; }
    .logo { font-size:30px; background:#203756; padding:10px 13px; border-radius:16px; }
    h1 { margin:0; font-size:clamp(28px,5vw,42px); letter-spacing:-1px; }
    .tag { color:var(--muted); margin:4px 0 0; }
    .card { background:rgba(19,30,53,.94); border:1px solid var(--line);
      border-radius:24px; padding:clamp(20px,4vw,34px); box-shadow:0 22px 70px #0005; }
    label { display:block; font-weight:650; margin:0 0 10px; }
    .row { display:flex; gap:10px; }
    input { flex:1; min-width:0; border:1px solid #3a4c6c; background:#091326;
      color:var(--text); border-radius:12px; padding:15px; font-size:16px; outline:none; }
    input:focus { border-color:#7ab7ff; box-shadow:0 0 0 3px #7ab7ff22; }
    button { border:0; border-radius:12px; padding:0 22px; background:#6ba8ff;
      color:#061225; font-size:15px; font-weight:800; cursor:pointer; }
    button:hover { filter:brightness(1.08); }
    .hint { color:var(--muted); font-size:13px; margin:10px 0 0; }
    .result { margin-top:24px; border:1px solid var(--line); border-radius:18px; padding:20px; }
    .status { display:flex; align-items:center; gap:10px; font-size:21px; font-weight:800; }
    .dot { width:13px; height:13px; border-radius:50%; display:inline-block; }
    .LOW .dot { background:var(--green); box-shadow:0 0 14px #35d49a88; }
    .MODERATE .dot { background:var(--orange); box-shadow:0 0 14px #ffb45488; }
    .DANGER .dot { background:var(--red); box-shadow:0 0 14px #ff667888; }
    .LOW .status { color:var(--green); } .MODERATE .status { color:var(--orange); }
    .DANGER .status { color:var(--red); }
    ul { padding-left:21px; line-height:1.7; }
    .footer { color:var(--muted); font-size:12px; text-align:center; margin-top:18px; line-height:1.6; }
    .error { margin-top:15px; padding:12px; color:#ffd2d8; background:#70283a55; border-radius:10px; }
    @media(max-width:520px) { .row { flex-direction:column; } button { padding:14px; } }
  </style>
</head>
<body><main class="wrap">
  <header class="brand"><div class="logo">🛡️</div><div><h1>SafeURL</h1>
    <p class="tag">Pause. Check. Click with care.</p></div></header>
  <section class="card">
    <form method="post">
      <label for="url">Enter a URL to check</label>
      <div class="row">
        <input id="url" name="url" type="text" placeholder="https://example.com"
               value="{{ submitted }}" autocomplete="url" required>
        <button type="submit">Check URL</button>
      </div>
      <p class="hint">SafeURL checks the address text for common warning signs. It never opens the submitted website.</p>
    </form>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    {% if result %}
    <section class="result {{ result.level }}">
      <div class="status"><span class="dot"></span>{{ result.label }}</div>
      <p>{{ result.summary }}</p>
      <strong>Findings</strong>
      <ul>{% for item in result.findings %}<li>{{ item }}</li>{% endfor %}</ul>
      <p class="hint">This is a preliminary heuristic check, not a definitive security verdict. Verify the domain through a trusted source before entering passwords or payment details.</p>
    </section>
    {% endif %}
  </section>
  <p class="footer">SafeURL · Built by Aditi Kumari<br>Do not enter confidential information on a site you do not trust.</p>
</main></body></html>
"""

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "banking", "password",
    "wallet", "payment", "signin", "confirm", "gift", "bonus", "free"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "shorturl.at", "cutt.ly"
}
RISKY_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".country"}

def check_url(raw_url: str) -> dict:
    """Classify a URL string using transparent, simple heuristics."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("Please enter a URL.")

    candidate = raw_url if "://" in raw_url else "https://" + raw_url
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid web address, such as https://example.com.")
    if any(ch.isspace() for ch in raw_url):
        raise ValueError("The URL cannot contain spaces.")

    host = parsed.hostname.lower().rstrip(".")
    findings = []
    score = 0

    if parsed.scheme != "https":
        findings.append("The address uses HTTP rather than HTTPS.")
        score += 2
    else:
        findings.append("The address uses HTTPS (this encrypts the connection but does not prove the site is trustworthy).")

    if "@" in parsed.netloc:
        findings.append("The address contains '@', which can be used to disguise the destination.")
        score += 3

    try:
        ipaddress.ip_address(host)
        findings.append("The host is an IP address instead of a recognizable domain name.")
        score += 2
    except ValueError:
        pass

    if host in SHORTENERS:
        findings.append("This is a URL-shortening domain, so the final destination is not visible here.")
        score += 2

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("The domain contains an internationalized/punycode label; check for look-alike characters.")
        score += 2

    if host.count(".") >= 4:
        findings.append("The hostname has many subdomain levels.")
        score += 1

    if len(raw_url) > 120:
        findings.append("The URL is unusually long.")
        score += 1

    if re.search(r"[\-_.]{2,}", host):
        findings.append("The hostname contains repeated separators.")
        score += 1

    matching_words = sorted(word for word in SUSPICIOUS_WORDS if word in host or word in parsed.path.lower())
    if matching_words:
        findings.append("Security-sensitive words appear in the address: " + ", ".join(matching_words) + ".")
        score += min(2, len(matching_words))

    if any(host.endswith(tld) for tld in RISKY_TLDS):
        findings.append("The domain uses a TLD sometimes seen in unwanted links; a TLD alone is not proof of danger.")
        score += 1

    if not findings:
        findings.append("No warning signs from this small set of checks were detected.")

    if score >= 5:
        level, label, summary = "DANGER", "🔴 High caution", "Several warning signs were detected. Avoid interacting until you verify the address independently."
    elif score >= 2:
        level, label, summary = "MODERATE", "🟠 Use caution", "Some warning signs were detected. Check the exact domain and destination before continuing."
    else:
        level, label, summary = "LOW", "💚 Fewer warning signs", "Few warning signs were detected by these basic checks. This does not guarantee the website is safe."

    return {"level": level, "label": label, "summary": summary, "findings": findings}

@app.route("/", methods=["GET", "POST"])
def index():
    submitted, result, error = "", None, None
    if request.method == "POST":
        submitted = request.form.get("url", "").strip()
        try:
            result = check_url(submitted)
        except ValueError as exc:
            error = str(exc)
    return render_template_string(PAGE, submitted=submitted, result=result, error=error)

@app.route("/health")
def health():
    return {"status": "ok", "app": "SafeURL"}

if __name__ == "__main__":
    # Local development server. For public deployment, use a production WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=False)
