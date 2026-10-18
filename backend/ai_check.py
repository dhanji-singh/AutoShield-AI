"""One small provider request using synthetic data; never prints credentials."""
from scan_ai import AIUnavailable, review_scan

if __name__ == "__main__":
    try:
        result = review_scan({"status": "completed", "report": {
            "coverage": {"pages": 0}, "limitations": ["Synthetic connectivity test; no website scanned."],
            "findings": []}})
    except AIUnavailable as exc:
        print("AI check failed:", exc)
        raise SystemExit(1)
    print(f"AI check OK: {result['provider']} / {result['model']}")
