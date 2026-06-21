from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)


def generate_pdf(
        findings,
        score,
        risk):

    doc = SimpleDocTemplate(
        "Security_Report.pdf"
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "SecureCodeAnalyzer Report",
            styles['Title']
        )
    )

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            f"Security Score : {score}/100",
            styles['Normal']
        )
    )

    content.append(
        Paragraph(
            f"Overall Risk : {risk}",
            styles['Normal']
        )
    )

    content.append(
        Spacer(1, 20)
    )

    for item in findings:

        content.append(
            Paragraph(
                f"<b>File:</b> {item['file']}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"<b>Issue:</b> {item['issue']}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"<b>Severity:</b> {item['severity']}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"<b>OWASP:</b> {item['owasp']}",
                styles['Normal']
            )
        )

        content.append(
            Paragraph(
                f"<b>Recommended Fix:</b> {item['remedy']}",
                styles['Normal']
            )
        )

        content.append(
            Spacer(1, 15)
        )

    doc.build(content)