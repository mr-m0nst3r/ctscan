"""Compiled rule engine."""

from __future__ import annotations

import json
from pathlib import Path

from ctscan.dns.resolver import DnsResolver
from ctscan.models import CertRecord
from ctscan.rules.builtins import build_builtins


class RuleEngine:
    _SAFE_GLOBALS = {"__builtins__": {}}

    def __init__(
        self,
        dns: DnsResolver,
        *,
        rule_str: str | None = None,
        rule_file: str | Path | None = None,
    ):
        self.dns = dns
        self.builtins = build_builtins(dns)
        self.rules: list[dict] = []
        self._compiled: list[tuple[str, object]] = []

        if rule_str:
            self.rules.append({"name": "query", "filter": rule_str})
        if rule_file:
            self._load_file(rule_file)
        self._compile_all()

    def _load_file(self, path: str | Path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, list):
            self.rules.extend(data)
        elif isinstance(data, dict) and "rules" in data:
            self.rules.extend(data["rules"])

    def _compile_all(self) -> None:
        self._compiled = []
        for rule in self.rules:
            name = rule.get("name", "unnamed")
            expr = rule.get("filter", "True")
            try:
                code = compile(expr, f"<rule:{name}>", "eval")
                self._compiled.append((name, code))
            except SyntaxError as exc:
                raise SyntaxError(f"Rule '{name}' syntax error: {exc}") from exc

    def match_domain(self, cert: CertRecord, domain: str) -> tuple[bool, str]:
        if not self._compiled:
            return True, "default"
        ctx = cert.as_rule_context(domain)
        env = {**ctx, **self.builtins}
        for name, code in self._compiled:
            try:
                if eval(code, self._SAFE_GLOBALS, env):
                    return True, name
            except Exception as exc:
                raise RuntimeError(f"Rule '{name}' evaluation error: {exc}") from exc
        return False, ""
