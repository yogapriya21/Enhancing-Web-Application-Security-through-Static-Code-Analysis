import os
import json

def run_bandit(folder):

    os.system(
        f'bandit -r "{folder}" -f json -o reports/bandit.json'
    )

def run_semgrep(folder):

    os.system(
        f'semgrep scan "{folder}" --json > reports/semgrep.json'
    )

def load_findings():

    findings = []

    try:

        with open(
            "reports/bandit.json",
            "r"
        ) as f:

            data = json.load(f)

        for item in data.get(
            "results",
            []
        ):

            findings.append({

                "file":
                item.get(
                    "filename",
                    "Unknown"
                ),

                "issue":
                item.get(
                    "issue_text",
                    "Unknown"
                ),

                "severity":
                item.get(
                    "issue_severity",
                    "LOW"
                )

            })

    except:
        pass

    try:

        with open(
            "reports/semgrep.json",
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        for item in data.get(
            "results",
            []
        ):

            findings.append({

                "file":
                item.get(
                    "path",
                    "Unknown"
                ),

                "issue":
                item.get(
                    "check_id",
                    "Unknown"
                ),

                "severity":
                item.get(
                    "extra",
                    {}
                ).get(
                    "severity",
                    "LOW"
                )

            })

    except:
        pass

    return findings