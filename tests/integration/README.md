# Live WAF integration tests

These tests need the running Docker lab and send requests to ports 8080–8082.
They are deliberately separate from the default unit-test discovery.

```text
python -m unittest discover -s tests/integration -v
```

An apostrophe regression may be reported as a known application issue. That
does not establish a passing benign regression. HTTP 403 alone does not identify
which WAF rule blocked the request; use `tests/verify_candidate_evidence.py`
for hash and rule-ID attribution after installing candidate content.
