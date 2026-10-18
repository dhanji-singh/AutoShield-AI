"""Shared scanner defaults; explicit scan options override environment settings."""

import os


def page_limit(value):
    if value is None:
        return 0
    if type(value) is not int or value < 0:
        raise ValueError("max_pages must be a non-negative integer or null")
    return value


def default_max_pages():
    value = os.getenv("SCANNER_MAX_PAGES", "200").strip().lower()
    return 0 if value in ("none", "null", "unlimited") else page_limit(int(value))


def default_verify_ssl():
    value = os.getenv("SCANNER_VERIFY_SSL", "true").strip().lower()
    if value not in ("true", "false", "1", "0"):
        raise ValueError("SCANNER_VERIFY_SSL must be true or false")
    return value in ("true", "1")
