# config.py
import os

DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"