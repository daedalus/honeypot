import logging
import sys
from pathlib import Path

# Ensure we can import honeypot
sys.path.insert(0, str(Path(__file__).parent))

logging.disable(logging.CRITICAL)
