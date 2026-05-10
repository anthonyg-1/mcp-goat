/*
 * MCP Configuration Risk Detection
 * Detects dangerous MCP server configuration patterns where stdio servers
 * execute code through shells with unsafe parameters.
 */

rule MCPConfigRisk
{
    meta:
        name        = "MCP Config Risk"
        author      = "mcp-goat training rules"
        severity    = "CRITICAL"
        description = "Detects dangerous MCP config: shell interpreters with code-execution flags"

    strings:
        $bash_cmd  = "\"command\": \"bash\""
        $sh_cmd    = "\"command\": \"sh\""
        $python    = "\"command\": \"python\""
        $node_cmd  = "\"command\": \"node\""
        $pwsh      = "\"command\": \"powershell\""

        $flag_c    = "\"-c\""
        $flag_e    = "\"-e\""

        $curl      = "\"curl\""
        $wget      = "\"wget\""
        $base64    = "\"base64\""
        $pipe_arg  = "\"|\""

        $calc      = "calc.exe"

    condition:
        ($bash_cmd or $sh_cmd or $python or $node_cmd or $pwsh) and
        ($flag_c or $flag_e or $curl or $wget or $base64 or $pipe_arg) or
        $calc
}
