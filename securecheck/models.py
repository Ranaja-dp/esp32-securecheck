from dataclasses import asdict, dataclass
from typing import Any

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    message: str
    path: str
    line: int
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
