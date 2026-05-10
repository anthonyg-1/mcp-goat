/*
 * Cross-Domain Contamination / Mixed Security Schemes Detection
 * Detects MCP resources spanning internal and external HTTP origins.
 */

rule CrossDomainContamination
{
    meta:
        name        = "Cross-Domain Contamination"
        author      = "mcp-goat training rules"
        severity    = "HIGH"
        description = "Detects resources spanning internal (corp/local) and external domains"

    strings:
        $int_local    = /https?:\/\/[^\s\/]+\.local[\s\/]/
        $int_corp     = /https?:\/\/[^\s\/]+\.corp[\s\/\.]/
        $int_internal = /https?:\/\/[^\s\/]+\.internal[\s\/]/
        $int_loopback = /https?:\/\/127\.[0-9]+\.[0-9]+\.[0-9]+/
        $int_rfc1918  = /https?:\/\/10\.[0-9]+\.[0-9]+\.[0-9]+/

        $ext_com      = /https?:\/\/[^\s\/]+\.com[\s\/]/
        $ext_net      = /https?:\/\/[^\s\/]+\.net[\s\/]/
        $ext_io       = /https?:\/\/[^\s\/]+\.io[\s\/]/
        $ext_xyz      = /https?:\/\/[^\s\/]+\.xyz[\s\/]/
        $ext_org      = /https?:\/\/[^\s\/]+\.org[\s\/]/

        $cdn          = /cloudfront|fastly|akamai|cloudflare|amazonaws/i

    condition:
        (
            ($int_local or $int_corp or $int_internal or
             $int_loopback or $int_rfc1918) and
            ($ext_com or $ext_net or $ext_io or $ext_xyz or $ext_org)
        ) and not $cdn
}


rule MixedSecuritySchemes
{
    meta:
        name        = "Mixed HTTP/HTTPS Security Schemes"
        author      = "mcp-goat training rules"
        severity    = "MEDIUM"
        description = "Detects simultaneous use of insecure HTTP and secure HTTPS"

    strings:
        $http   = "http://"
        $https  = "https://"
        $cdn    = /cloudfront|fastly|akamai|cloudflare/i

    condition:
        $http and $https and not $cdn
}
