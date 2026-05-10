/*
 * Command Injection Detection
 * Detects shell injection patterns and dangerous code execution functions.
 */

rule CommandInjection
{
    meta:
        name        = "Command Injection"
        author      = "mcp-goat training rules"
        severity    = "CRITICAL"
        description = "Detects command injection vectors: shell operators, exec functions, reverse shells"

    strings:
        $chain_and   = "&&"
        $chain_or    = "||"
        $semicolon   = /;\s*[a-zA-Z]/
        $pipe_cmd    = /\|\s*[a-zA-Z]/

        $os_system   = "os.system"
        $subprocess  = "subprocess."
        $eval_py     = /eval\s*\(/

        $bash_c      = "bash -c"
        $sh_c        = "sh -c"
        $bin_bash    = "/bin/bash"
        $bin_sh      = "/bin/sh"

        $bash_redir  = /bash\s+-i\s*>&/
        $nc_exec     = "nc -e"
        $nc_listen   = "nc -l"

        $rm_rf       = "rm -rf"
        $chmod_777   = "chmod 777"
        $sudo_rm     = /sudo\s+rm/

        $python_c    = /python[23]?\s+-c/
        $node_e      = "node -e"
        $php_r       = "php -r"
        $perl_e      = "perl -e"

        $cat_passwd  = /cat\s+.*passwd/
        $cat_shadow  = /cat\s+.*shadow/

        $legit       = /read_file|write_file|create_file|push_files|git_commit/

    condition:
        $chain_and or $chain_or or $pipe_cmd or $semicolon or
        $bash_c or $sh_c or $bin_bash or $bin_sh or
        $bash_redir or $nc_exec or $nc_listen or
        $rm_rf or $chmod_777 or $sudo_rm or
        $python_c or $node_e or $php_r or $perl_e or
        $cat_passwd or $cat_shadow or
        ($os_system or $subprocess or $eval_py) and not $legit
}
