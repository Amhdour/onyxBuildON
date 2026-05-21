from __future__ import annotations

from onyx.security_layer.decisions.models import SecurityDecision


class DecisionService:
    def __init__(self) -> None:
        self._decisions: list[SecurityDecision] = []

    def create(self, decision: SecurityDecision) -> SecurityDecision:
        self._decisions.append(decision)
        return decision

    def list_all(self) -> list[SecurityDecision]:
        return list(self._decisions)
