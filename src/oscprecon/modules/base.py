from __future__ import annotations

from abc import ABC, abstractmethod

from oscprecon.models import Command, Finding, Port, ScanResults, Target


class Module(ABC):
    name: str

    @abstractmethod
    def triggers(self, scan_results: ScanResults) -> bool: ...

    @abstractmethod
    def commands(self, target: Target, ports: list[Port]) -> list[Command]: ...

    @abstractmethod
    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]: ...

    @abstractmethod
    def suggest(self, findings: list[Finding]) -> list[str]: ...
