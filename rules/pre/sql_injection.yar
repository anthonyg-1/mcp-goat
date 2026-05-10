/*
 * SQL Injection Detection
 * Detects SQL injection patterns in resource URIs and tool metadata.
 */

rule SQLInjection
{
    meta:
        name        = "Advanced SQL Injection Detection"
        author      = "mcp-goat training rules"
        severity    = "CRITICAL"
        description = "Detects SQL injection: union attacks, boolean logic, comment truncation"

    strings:
        $kw_select  = /SELECT\s+/i
        $kw_insert  = /INSERT\s+INTO/i
        $kw_drop    = /DROP\s+(TABLE|DATABASE)/i

        $union_sel  = /UNION\s+SELECT/i
        $union_all  = /UNION\s+ALL\s+SELECT/i

        $or_one_eq  = /OR\s+1\s*=\s*1/i
        $or_true    = /OR\s+'1'\s*=\s*'1'/i
        $and_one    = /AND\s+1\s*=\s*1/i

        $comment_dd = "--"
        $comment_ml = "/*"

        $sleep_fn   = /SLEEP\s*\(/i
        $waitfor    = /WAITFOR\s+DELAY/i

        $stacked    = /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i

        $info_schema = /information_schema/i
        $pg_catalog  = /pg_catalog/i

        $legit      = /database_tool|sql_client|query_builder|db_admin|schema_manager/i

    condition:
        (
            ($kw_select or $kw_insert) and
            ($or_one_eq or $or_true or $and_one or $comment_dd or $comment_ml or
             $union_sel or $union_all or $stacked)
        ) and not $legit or
        $kw_drop or
        $info_schema or $pg_catalog or
        $sleep_fn or $waitfor
}
