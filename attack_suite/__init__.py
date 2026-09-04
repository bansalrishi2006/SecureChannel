from __future__ import annotations

from secure_core.events import events

from .report import AttackReport, AttackResult, AttackTarget


def emit_attack_start(attack: str, target: AttackTarget) -> None:
    events.emit(
        "attack.start",
        connection_id=f"{target.variant}:{attack}",
        variant=target.variant,
        attack=attack,
        target_variant=target.variant,
    )


def emit_attack_result(attack: str, target: AttackTarget, result: AttackResult) -> AttackResult:
    events.emit(
        "attack.result",
        connection_id=f"{target.variant}:{attack}",
        variant=target.variant,
        attack=attack,
        target_variant=target.variant,
        outcome=result.outcome,
        details=result.details,
    )
    return result
