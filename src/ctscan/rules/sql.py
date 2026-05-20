"""SQL-like queries → Python expressions (for safe compiled evaluation)."""

import re


def _sql_strings_to_python_repr(query: str) -> str:
    """
    Convert SQL single-quoted literals to Python repr(), honoring SQL '' → ' escaping.

    Without this, issuer_org == 'Let''s Encrypt' becomes adjacent literals
    'Let' + 's Encrypt' => Lets Encrypt, which never matches the real CA name.
    """

    def repl(m: re.Match) -> str:
        inner = m.group(1).replace("''", "'")
        return repr(inner)

    return re.sub(r"'((?:[^']|'')*)'", repl, query)


def parse_sql_query(query: str) -> str:
    query = query.strip()
    if query.upper().startswith("WHERE "):
        query = query[6:]

    query = _sql_strings_to_python_repr(query)

    def replace_like(match: re.Match) -> str:
        field = match.group(1)
        pattern = match.group(2).strip("\"'")
        regex = pattern.replace(".", r"\.").replace("%", ".*").replace("_", ".")
        return f'matches({field}, "^{regex}$")'

    query = re.sub(
        r"(\w+)\s+LIKE\s+(\"[^\"]+\"|'[^']+')",
        replace_like,
        query,
        flags=re.IGNORECASE,
    )

    def replace_not_like(match: re.Match) -> str:
        field = match.group(1)
        pattern = match.group(2).strip("\"'")
        regex = pattern.replace(".", r"\.").replace("%", ".*").replace("_", ".")
        return f'not matches({field}, "^{regex}$")'

    query = re.sub(
        r"(\w+)\s+NOT\s+LIKE\s+(\"[^\"]+\"|'[^']+')",
        replace_not_like,
        query,
        flags=re.IGNORECASE,
    )

    query = re.sub(r"(\w+)\s+IN\s+\(([^)]+)\)", r"\1 in (\2)", query, flags=re.IGNORECASE)
    query = re.sub(
        r"(\w+)\s+NOT\s+IN\s+\(([^)]+)\)",
        r"\1 not in (\2)",
        query,
        flags=re.IGNORECASE,
    )
    query = re.sub(r"(\w+)\s+IS\s+NULL", r"\1 is None", query, flags=re.IGNORECASE)
    query = re.sub(r"(\w+)\s+IS\s+NOT\s+NULL", r"\1 is not None", query, flags=re.IGNORECASE)
    query = re.sub(r"(?<![=!<>])(=)(?!=)", "==", query)
    query = re.sub(r"\btrue\b", "True", query, flags=re.IGNORECASE)
    query = re.sub(r"\bfalse\b", "False", query, flags=re.IGNORECASE)
    query = re.sub(r"\bAND\b", " and ", query, flags=re.IGNORECASE)
    query = re.sub(r"\bOR\b", " or ", query, flags=re.IGNORECASE)
    query = re.sub(r"\bNOT\b", " not ", query, flags=re.IGNORECASE)
    return query
