"""
Configuration settings for the Ransomware Detection & Mitigation Framework.
"""

import os

# Model paths
CNN_MODEL_PATH = "models/cnn_model.h5"
LSTM_MODEL_PATH = "models/lstm_model.h5"

# File extensions to monitor
MONITOR_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", 
    ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".pdf"
]

# Paths to ignore during scanning
IGNORE_PATHS = [
    "Windows", "Program Files", "Program Files (x86)", 
    "$Recycle.Bin", "ProgramData", "AppData"
]

# Alert levels
ALERT_LEVELS = {
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.7
}

# Default thresholds
DEFAULT_CNN_THRESHOLD = 0.7
DEFAULT_LSTM_THRESHOLD = 0.6

# Maximum file size to scan (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

# Quarantine location
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")