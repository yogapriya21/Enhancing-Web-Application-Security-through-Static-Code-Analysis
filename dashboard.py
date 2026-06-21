from flask import Flask, render_template, request, send_file
import os
import zipfile
import shutil
import matplotlib.pyplot as plt

from scanner import (
    run_bandit,
    run_semgrep,
    load_findings
)

from owasp_mapper import (
    map_owasp,
    get_remedy
)

from report_generator import (
    generate_pdf
)

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
EXTRACT_FOLDER = "extracted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)
os.makedirs("reports", exist_ok=True)
os.makedirs("static", exist_ok=True)


def detect_languages(folder):

    languages = set()

    for root, dirs, files in os.walk(folder):

        for file in files:

            if file.endswith(".py"):
                languages.add("Python")

            elif file.endswith(".js"):
                languages.add("JavaScript")

            elif file.endswith(".php"):
                languages.add("PHP")

            elif file.endswith(".java"):
                languages.add("Java")

            elif file.endswith(".ts"):
                languages.add("TypeScript")

            elif file.endswith(".html"):
                languages.add("HTML")

            elif file.endswith(".css"):
                languages.add("CSS")

    return sorted(list(languages))


def create_chart(high, medium, low):

    plt.style.use("default")

    fig, ax = plt.subplots(figsize=(10, 4))

    fig.patch.set_facecolor("#212529")
    ax.set_facecolor("#212529")

    categories = [
        "High",
        "Medium",
        "Low"
    ]

    values = [
        high,
        medium,
        low
    ]

    colors = [
        "#dc3545",
        "#ffc107",
        "#198754"
    ]

    bars = ax.barh(
        categories,
        values,
        color=colors
    )

    ax.set_title(
        "Vulnerability Severity Distribution",
        fontsize=16,
        color="white",
        fontweight="bold"
    )

    ax.set_xlabel(
        "Number of Findings",
        color="white"
    )

    ax.tick_params(
        colors="white"
    )

    for bar in bars:

        width = bar.get_width()

        ax.text(
            width + 1,
            bar.get_y() + bar.get_height() / 2,
            str(int(width)),
            color="white",
            va="center",
            fontsize=12
        )

    plt.tight_layout()

    plt.savefig(
        "static/chart.png",
        facecolor="#212529"
    )

    plt.close()


@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route("/architecture")
def architecture():

    return render_template(
        "architecture.html"
    )


@app.route("/cicd")
def cicd():

    return render_template(
        "cicd.html"
    )


@app.route("/download")
def download():

    return send_file(
        "Security_Report.pdf",
        as_attachment=True
    )


@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    file = request.files["zipfile"]

    if not file:

        return "No file uploaded"

    filepath = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(filepath)

    # Clear previous extraction

    if os.path.exists(EXTRACT_FOLDER):

        shutil.rmtree(EXTRACT_FOLDER)

    os.makedirs(EXTRACT_FOLDER)

    # Extract ZIP

    with zipfile.ZipFile(
        filepath,
        "r"
    ) as zip_ref:

        zip_ref.extractall(
            EXTRACT_FOLDER
        )

    # Detect languages

    languages = detect_languages(
        EXTRACT_FOLDER
    )

    # Run scanners

    run_bandit(
        EXTRACT_FOLDER
    )

    run_semgrep(
        EXTRACT_FOLDER
    )

    findings = load_findings()

    print("=" * 60)
    print("TOTAL FINDINGS LOADED:", len(findings))
    print("=" * 60)

    high = 0
    medium = 0
    low = 0

    owasp_summary = {}

    for item in findings:

        severity = str(
            item.get(
                "severity",
                "LOW"
            )
        ).upper()

        # Semgrep mapping

        if severity == "ERROR":
            severity = "HIGH"

        elif severity == "WARNING":
            severity = "MEDIUM"

        elif severity == "INFO":
            severity = "LOW"

        item["severity"] = severity

        if severity == "HIGH":

            high += 1

        elif severity == "MEDIUM":

            medium += 1

        else:

            low += 1

        owasp = map_owasp(
            item["issue"]
        )

        remedy = get_remedy(
            item["issue"]
        )

        item["owasp"] = owasp
        item["remedy"] = remedy

        if owasp not in owasp_summary:

            owasp_summary[
                owasp
            ] = 0

        owasp_summary[
            owasp
        ] += 1

    # Security Score

    severity_points = (
        high * 10 +
        medium * 5 +
        low * 1
    )

    score = max(
        0,
        100 - severity_points
    )

    # Risk Classification

    if high > 0:

        risk = "HIGH"
        posture = "CRITICAL"

    elif medium > 0:

        risk = "MEDIUM"
        posture = "NEEDS IMPROVEMENT"

    else:

        risk = "LOW"
        posture = "SECURE"

    print(f"High Findings   : {high}")
    print(f"Medium Findings : {medium}")
    print(f"Low Findings    : {low}")
    print(f"Score           : {score}")

    # Generate chart

    create_chart(
        high,
        medium,
        low
    )

    # Generate PDF

    generate_pdf(
        findings,
        score,
        risk
    )

    return render_template(

        "results.html",

        findings=findings,

        languages=", ".join(
            languages
        ),

        total=len(
            findings
        ),

        high=high,

        medium=medium,

        low=low,

        score=score,

        risk=risk,

        posture=posture,

        owasp_summary=
        owasp_summary

    )


if __name__ == "__main__":

    app.run(
        debug=True
    )