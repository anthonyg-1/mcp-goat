/*
 * Secrets & Credential Leakage Detection
 * Detects hardcoded credentials and sensitive environment variable exposure
 * in MCP tool names, resource names, and configuration metadata.
 */

rule SecretsLeakage
{
    meta:
        name        = "Secrets Leakage Detection"
        author      = "mcp-goat training rules"
        severity    = "CRITICAL"
        description = "Detects hardcoded API keys, tokens, and credentials"

    strings:
        // AWS access key — starts with AKIA, 20 chars total
        $aws_access_key = /AKIA[0-9A-Z]{16}/

        // Generic API key assignment patterns
        $api_key_assign = /api[_\-]?key\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}/i

        // Bearer tokens
        $bearer_token = /Bearer\s+[A-Za-z0-9\-_\.]{20,}/

        // PEM private key headers
        $pem_private = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_ec      = "-----BEGIN EC PRIVATE KEY-----"

        // GitHub personal access tokens
        $github_pat = /gh[pousr]_[A-Za-z0-9_]{36}/

        // Hardcoded password patterns
        $hardcoded_pw = /password\s*[:=]\s*[A-Za-z0-9!@#$%^&*]{8,}/i

    condition:
        any of them
}


rule EnvironmentVariableLeakage
{
    meta:
        name        = "Environment Variable Leakage"
        author      = "mcp-goat training rules"
        severity    = "HIGH"
        description = "Detects credential-bearing environment variable names in metadata"

    strings:
        $aws_key_id  = "AWS_ACCESS_KEY_ID"
        $aws_secret  = "AWS_SECRET_ACCESS_KEY"
        $generic_api = /[A-Z][A-Z0-9_]{3,}_API_KEY/
        $generic_pw  = /[A-Z][A-Z0-9_]{3,}_PASSWORD/
        $generic_sec = /[A-Z][A-Z0-9_]{3,}_SECRET/
        $generic_tok = /[A-Z][A-Z0-9_]{3,}_TOKEN/
        $openai_key  = "OPENAI_API_KEY"
        $anthropic   = "ANTHROPIC_API_KEY"
        $stripe_key  = "STRIPE_SECRET_KEY"
        $db_url      = "DATABASE_URL"

    condition:
        any of them
}


rule SSHKeyExposure
{
    meta:
        name        = "SSH Key Exposure"
        author      = "mcp-goat training rules"
        severity    = "CRITICAL"
        description = "Detects SSH private key content or file path references"

    strings:
        $ssh_openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $id_rsa_path = ".ssh/id_rsa"
        $id_ed_path  = ".ssh/id_ed25519"
        $auth_keys   = "authorized_keys"

    condition:
        any of them
}
