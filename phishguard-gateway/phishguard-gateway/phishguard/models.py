"""Shared data structures."""
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class Finding:
    module: str      # header | auth | url | attachment | ml
    message: str
    points: int

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    score: int = 0
    verdict: str = "clean"          # clean | suspicious | malicious
    ml_probability: Optional[float] = None
    subject: str = ""
    sender: str = ""
    findings: List[Finding] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachments: List[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
