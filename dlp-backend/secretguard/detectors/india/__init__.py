"""Indian PII and financial-identifier detectors."""
from typing import List

from ..base import Detector
from .aadhaar import AadhaarDetector
from .bank_account import BankAccountDetector
from .gstin import GstinDetector
from .ifsc import IfscDetector
from .mobile import MobileDetector
from .pan import PanDetector
from .upi import UpiDetector

__all__ = [
    "AadhaarDetector", "PanDetector", "GstinDetector", "IfscDetector",
    "BankAccountDetector", "UpiDetector", "MobileDetector", "all_india_detectors",
]


def all_india_detectors() -> List[Detector]:
    return [AadhaarDetector(), PanDetector(), GstinDetector(), IfscDetector(),
            BankAccountDetector(), UpiDetector(), MobileDetector()]
