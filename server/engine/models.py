from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PureWindowsPath


@dataclass
class ProcessNode:
    guid: str #уникальный идентификатор процесса
    pid: int #идентификатор процесса
    image: str #полный путь к исполняемому файлу
    command_line: str #строка запуска с аргументами
    timestamp: datetime #время запуска 
    user: str #учетная запись 
    parent_guid: str | None = None
    parent: ProcessNode | None = field(default=None, repr=False)
    children: list[ProcessNode] = field(default_factory=list)

    @property
    def image_name(self) -> str:
        return PureWindowsPath(self.image).name # имя файла


@dataclass
class Alert:
    rule_name: str #название правила
    severity: str #уровень критичности (LOW, MEDIUM, HIGH, CRITICAL)
    mitre_technique: str #идентификатор по матрице MITRE ATT&CK
    description: str #понятное человеку описание того, что произошло 
    process: ProcessNode #узел ProcessNode
    lineage: list[ProcessNode] #цепочка предков (список list[ProcessNode])

    def to_dict(self) -> dict:
        return {
            "name" : self.rule_name,
            "severity" : self.severity,
            "mitre_technique" : self.mitre_technique,
            "description" : self.description, 
            "process" : {
                "guid" : self.process.guid,
                "pid": self.process.pid, 
                "image" : self.process.image,
                "command_line" : self.process.command_line,
                "user" : self.process.user,
                "timestamp" : self.process.timestamp.isoformat()
            },
            "lineage" : [f"{p.image_name} (PID: {p.pid})" for p in self.lineage]
        }

    