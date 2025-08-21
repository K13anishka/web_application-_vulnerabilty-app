import os
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from bs4 import BeautifulSoup
from fpdf import FPDF
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

app = Flask(__name__)
app.secret_key = "change-this-key"

# ---------- Auth (in-memory for demo) ----------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

USERS = {}  # {username: password}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

# ---------- Utility: basic scanner ----------
def safe_get(url, **kwargs):
    try:
        return requests.get(url, timeout=8, verify=False, **kwargs)
    except Exception as e:
        return None

SQL_ERR_MARKERS = [
    "you have an error in your sql syntax",
    "sql syntax",
    "mysql",
    "postgresql",
    "oracle",
    "sqlite",
    "sqlstate",
    "unclosed quotation mark"
]

def run_basic_scan(target_url: str):
    findings = []

    # Normalize
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url

    # Request
    r = safe_get(target_url)

    # 1) XSS (very naive reflected check via ?q=)
    xss_payload = "<script>alert(1)</script>"
    r_xss = safe_get(target_url, params={"q": xss_payload})
    if r_xss is not None and xss_payload in (r_xss.text or ""):
        findings.append({"name":"Cross-Site Scripting (XSS)","severity":"High","details":"Reflected payload echoed via parameter 'q'."})

    # 2) Clickjacking
    if r is not None:
        xfo = (r.headers.get("X-Frame-Options","") or "").lower()
        csp = (r.headers.get("Content-Security-Policy","") or "").lower()
        if ("deny" not in xfo and "sameorigin" not in xfo and "frame-ancestors" not in csp):
            findings.append({"name":"Clickjacking","severity":"Medium","details":"Missing X-Frame-Options and CSP frame-ancestors."})

    # 3) SQLi (error-based heuristic by adding a quote)
    if r is not None:
        test_url = target_url + ("'" if "?" in target_url else "/'")
        r_err = safe_get(test_url)
        if r_err is not None:
            body = (r_err.text or "").lower()
            if any(m in body for m in SQL_ERR_MARKERS):
                findings.append({"name":"SQL Injection (error-based)","severity":"High","details":"Potential DB error revealed when injecting a single quote."})

    # 4) CSRF (forms without tokens)
    if r is not None:
        soup = BeautifulSoup(r.text or "", "html.parser")
        forms = soup.find_all("form")
        if forms:
            tokenish = ("csrf","xsrf","token")
            vulnerable = 0
            for f in forms:
                combined = (f.get_text(" ") + str(f.attrs)).lower()
                if not any(t in combined for t in tokenish):
                    vulnerable += 1
            if vulnerable == len(forms):
                findings.append({"name":"Cross-Site Request Forgery (CSRF)","severity":"Medium","details":"Forms detected without visible anti-CSRF tokens."})

    # 5) Broken Authentication (very rough heuristic)
    if not target_url.startswith("https://"):
        findings.append({"name":"Broken Authentication (heuristic)","severity":"High","details":"Login indicators over non-HTTPS or weak signals."})

    # Summary
    summary = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for f in findings:
        sev = f["severity"]
        summary[sev] = summary.get(sev,0)+1

    return {"normalized_url": target_url, "findings": findings, "summary": summary}

# ---------- PDF Report ----------
def build_pdf_report(target_url, result):
    # Chart
    sev_order = ["Critical","High","Medium","Low"]
    counts = [result["summary"].get(s,0) for s in sev_order]
    plt.figure()
    plt.bar(sev_order, counts)
    plt.title("Vulnerabilities by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    chart_path = os.path.join("static","chart.png")
    os.makedirs("static", exist_ok=True)
    plt.savefig(chart_path, bbox_inches="tight")
    plt.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial","B",16)
    pdf.cell(0, 10, "Web Application Vulnerability Report", ln=True, align="C")
    pdf.ln(4)

    pdf.set_font("Arial","",12)
    pdf.cell(0, 8, f"Target URL: {target_url}", ln=True)
    pdf.cell(0, 8, f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(4)

    pdf.set_font("Arial","B",12)
    pdf.cell(0, 8, "Summary:", ln=True)
    pdf.set_font("Arial","",12)
    for k,v in result["summary"].items():
        pdf.cell(0, 7, f"- {k}: {v}", ln=True)
    pdf.ln(3)

    pdf.set_font("Arial","B",12)
    pdf.cell(0, 8, "Findings:", ln=True)
    pdf.set_font("Arial","",12)
    if not result["findings"]:
        pdf.cell(0, 7, "No obvious issues detected by basic checks.", ln=True)
    else:
        for f in result["findings"]:
            pdf.multi_cell(0, 7, f"• {f['name']} | Severity: {f['severity']}\n  Details: {f['details']}")
            pdf.ln(1)

    pdf.image(chart_path, x=40, w=130)

    mem = io.BytesIO()
    pdf.output(mem)
    mem.seek(0)
    return mem

# ---------- Routes ----------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not username or not password:
            flash("Username and password are required","error")
            return render_template("register.html")
        if username in USERS:
            flash("User already exists","error")
            return render_template("register.html")
        USERS[username] = password
        flash("Registration successful. Please login.","success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if username in USERS and USERS[username] == password:
            login_user(User(username))
            return redirect(url_for("dashboard"))
        flash("Invalid credentials","error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard", methods=["GET","POST"])
@login_required
def dashboard():
    if request.method == "POST":
        target = request.form.get("url","").strip()
        if not target:
            flash("Please enter a URL","error")
            return render_template("dashboard.html")
        result = run_basic_scan(target)
        session["last_result"] = result
        return render_template("report.html", url=result["normalized_url"], result=result)
    return render_template("dashboard.html")

@app.route("/download_report")
@login_required
def download_report():
    result = session.get("last_result")
    if not result:
        flash("No report available. Run a scan first.","error")
        return redirect(url_for("dashboard"))
    mem = build_pdf_report(result["normalized_url"], result)
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(mem, download_name=filename, as_attachment=True, mimetype="application/pdf")

# ---------- Main ----------
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app.run(debug=True)
