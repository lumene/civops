import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")

def load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Default config if file missing
        return {
            "scan_interval": 2.0,
            "scan_timeout": 2,
            "log_file": "logs/intercepts.csv",
            "gps_enabled": True,
            "ui_rotation_speed": 0.1,
            "demo_mode": False
        }

CONFIG = load_config()
