OWASP = {

    "password": "A02 Cryptographic Failures",
    "hardcoded": "A02 Cryptographic Failures",

    "sql": "A03 Injection",
    "shell": "A03 Injection",
    "command": "A03 Injection",
    "subprocess": "A03 Injection",

    "integrity": "A08 Software and Data Integrity Failures",

    "xss": "A03 Injection",

    "csrf": "A01 Broken Access Control",

    "authentication": "A07 Identification and Authentication Failures",

    "secret": "A02 Cryptographic Failures"
}

REMEDIES = {

    "password":
    "Avoid hardcoded passwords. Use environment variables or a secrets manager.",

    "hardcoded":
    "Store credentials securely using environment variables.",

    "sql":
    "Use parameterized queries or prepared statements to prevent SQL Injection.",

    "shell":
    "Avoid shell=True and validate all user inputs before execution.",

    "command":
    "Sanitize and validate user input before passing it to system commands.",

    "subprocess":
    "Use subprocess with argument lists instead of shell=True.",

    "integrity":
    "Add integrity and crossorigin attributes to external scripts and stylesheets.",

    "xss":
    "Sanitize user input and encode output before rendering.",

    "csrf":
    "Implement CSRF protection using secure tokens.",

    "authentication":
    "Enable MFA and strong authentication controls.",

    "secret":
    "Remove hardcoded secrets and use secure secret management."

}


def map_owasp(issue):

    issue = issue.lower()

    for key in OWASP:

        if key in issue:

            return OWASP[key]

    return "Unknown"


def get_remedy(issue):

    issue = issue.lower()

    for key in REMEDIES:

        if key in issue:

            return REMEDIES[key]

    return "Review the code and follow OWASP Secure Coding Guidelines."