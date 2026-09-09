from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

CAPTURE_DIR = BASE_DIR / "captures"
REPORT_DIR = BASE_DIR / "reports"

PACKET_COUNT = 100

CAPTURE_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)