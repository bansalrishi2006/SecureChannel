from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class AttackResult:
    attack: str
    outcome: str
    details: str


@dataclass
class AttackTarget:
    variant: str
    host: str
    port: int
    ca_cert_pem: bytes
    client_identity: object
    client_cls: type


@dataclass
class AttackReport:
    target_variant: str
    results: list[AttackResult]

    def to_json(self) -> str:
        return json.dumps({"target_variant": self.target_variant, "results": [asdict(r) for r in self.results]}, indent=2)

    def to_markdown(self) -> str:
        lines = [f"# Attack Report ({self.target_variant})", "", "| Attack | Outcome | Details |", "|---|---|---|"]
        for r in self.results:
            lines.append(f"| {r.attack} | {r.outcome} | {r.details} |")
        return "\n".join(lines) + "\n"


def aggregate_reports(target_variant: str, results: Iterable[AttackResult], output_dir: str | Path) -> AttackReport:
    report = AttackReport(target_variant=target_variant, results=list(results))
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{target_variant}_attack_report.json").write_text(report.to_json(), encoding="utf-8")
    (out / f"{target_variant}_attack_report.md").write_text(report.to_markdown(), encoding="utf-8")
    return report
