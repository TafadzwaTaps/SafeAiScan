"""
config.py — Application configuration
========================================
DEV_MODE has been removed. All plan gates are enforced in production.
Configuration is read from environment variables only.
"""

import os

# App base URL for redirect links (e.g. PayPal return URLs)
APP_BASE_URL: str = os.getenv("APP_BASE_URL", "http://localhost:3000")
