import re

# ──────────────────────────────────────────────
# PATTERNS
# ──────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg::syntaxerror",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlite3::exception",
    r"ora-[0-9]{4,5}",
]

DISCLOSURE_PATTERNS = [
    r"php/[0-9]+\.[0-9]+",
    r"apache/[0-9]+\.[0-9]+",
    r"nginx/[0-9]+\.[0-9]+",
    r"traceback",
    r"exception",
]

XSS_REFLECTION_PATTERNS = [
    r"<script>",
    r"javascript:",
    r"onerror=",
    r"alert\(",
]

SENSITIVE_PATH_PATTERNS = [
    r"\.env",
    r"\.git",
    r"/admin",
    r"/backup",
]

# ──────────────────────────────────────────────
# CHECKS
# ──────────────────────────────────────────────

def check_sql_errors(response):
    body = response.get("body", "").lower()
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, body):
            return {
                "type": "sql_error",
                "severity": "high",
                "description": "SQL error exposto",
                "evidence": pattern
            }
    return None


def check_xss_reflection(response):
    body = response.get("body", "").lower()
    for pattern in XSS_REFLECTION_PATTERNS:
        if re.search(pattern, body):
            return {
                "type": "xss_reflection",
                "severity": "high",
                "description": "Possível XSS refletido",
                "evidence": pattern
            }
    return None


def check_information_disclosure(response):
    findings = []
    body = response.get("body", "").lower()
    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

    for pattern in DISCLOSURE_PATTERNS:
        if re.search(pattern, body):
            findings.append({
                "type": "info_disclosure",
                "severity": "medium",
                "description": "Informação exposta",
                "evidence": pattern
            })

    # headers
    if "server" in headers:
        findings.append({
            "type": "header_disclosure",
            "severity": "low",
            "description": "Header server exposto",
            "evidence": headers["server"]
        })

    return findings


def check_sensitive_path(response):
    url = response.get("url", "").lower()
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, url):
            return {
                "type": "sensitive_path",
                "severity": "medium",
                "description": "Caminho sensível",
                "evidence": url
            }
    return None


# ──────────────────────────────────────────────
# CORE
# ──────────────────────────────────────────────

def analyze_response(response):
    findings = []

    for func in [
        check_sql_errors,
        check_xss_reflection,
        check_sensitive_path
    ]:
        r = func(response)
        if r:
            findings.append(r)

    findings.extend(check_information_disclosure(response))

    score = len(findings) * 5

    return {
        "url": response.get("url"),
        "status_code": response.get("status_code"),
        "findings": findings,
        "risk_score": score,
        "risk_level": "medium" if score else "none"
    }


# ──────────────────────────────────────────────
# MULTI + IA
# ──────────────────────────────────────────────

try:
    from ai.llm_client import analyze_with_ai
except:
    analyze_with_ai = None


def analyze_multiple(responses, use_ai=False):
    results = []

    for r in responses:
        result = analyze_response(r)

        if use_ai and analyze_with_ai:
            try:
                result["ai_analysis"] = analyze_with_ai(r)
            except:
                result["ai_analysis"] = "Erro na IA"

        results.append(result)

    return results
