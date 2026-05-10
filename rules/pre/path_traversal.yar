/*
 * Path Traversal Vulnerability Detection
 * Detects directory traversal sequences and access to sensitive system paths.
 */

rule PathTraversalVulnerability
{
    meta:
        name        = "Path Traversal Vulnerability"
        author      = "mcp-goat training rules"
        severity    = "HIGH"
        description = "Detects directory traversal sequences and sensitive path access"

    strings:
        $traversal_unix    = "../"
        $traversal_win     = "..\\"
        $traversal_encoded = "%2e%2e%2f"
        $traversal_dbl_enc = "%252e%252e%252f"

        $etc_dir    = "/etc/"
        $root_dir   = "/root/"
        $proc_dir   = "/proc/"

        $passwd     = "/etc/passwd"
        $shadow     = "/etc/shadow"
        $ssh_dir    = "/.ssh/"

        $win_sam    = "C:\\Windows\\System32\\SAM"

        $fopen      = "fopen"
        $readfile   = "readFile"
        $file_get   = "file_get_contents"

    condition:
        $traversal_unix or $traversal_win or $traversal_encoded or $traversal_dbl_enc or
        $passwd or $shadow or $ssh_dir or $win_sam or
        ($fopen or $readfile or $file_get) and ($etc_dir or $root_dir or $proc_dir)
}
