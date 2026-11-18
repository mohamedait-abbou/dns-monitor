"""DNS Monitor - real-time DNS traffic analysis and threat detection."""

from .analyzer import Analyzer
from .config import Config
from .detector import DetectionEngine
from .models import Alert, DNSQuery

__version__ = "1.0.0"
__all__ = ["Alert", "Analyzer", "Config", "DNSQuery", "DetectionEngine", "__version__"]
