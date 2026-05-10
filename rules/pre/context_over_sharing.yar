/*
 * Context Over-Sharing Detection
 * Detects MCP resources that expose shared context across sessions or agents
 * with no per-session isolation.
 *
 * OWASP MCP10:2025 – Context Injection & Over-Sharing
 */

rule ContextOverSharing
{
    meta:
        name        = "Context Over-Sharing"
        author      = "mcp-goat training rules"
        severity    = "HIGH"
        description = "Detects resources exposing shared context across sessions without isolation"

    strings:
        $shared_ctx  = /shared[_\-\[]context/i
        $global_ctx  = /global[_\-\[]context/i
        $no_isolation = "no_isolation"
        $all_visible  = /all[_\-\[]users[_\-\[]visible|all[_\-\[]agents[_\-\[]visible/i
        $cross_session = /cross[_\-\[]session|cross[_\-\[]agent[_\-\[]context/i

    condition:
        ($shared_ctx or $global_ctx or $cross_session) and
        ($no_isolation or $all_visible) or
        $cross_session
}
