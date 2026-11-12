from typing import List

from .base import Detector
from .india import all_india_detectors
from .secrets import SecretDetector


def default_detectors(include_secrets: bool = True, include_india: bool = True) -> List[Detector]:
    detectors: List[Detector] = []
    if include_secrets:
        detectors.append(SecretDetector())
    if include_india:
        detectors.extend(all_india_detectors())
    return detectors
