FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home appuser \
    && mkdir -p /app/data \
    && chown appuser:appuser /app/data

COPY --chown=appuser:appuser main.py detector.py findings.py proposals.py rule_compiler.py validation.py evidence.py .
COPY --chown=appuser:appuser gemini_check.py ai_check.py .

COPY --chown=appuser:appuser scan_engine.py scan_store.py scan_ai.py scan_api.py scan_report.py scan_compare.py scan_checks.py scan_identity.py scan_settings.py scan_gateway_policy.py scan_mcp_server.py scan_mcp_client.py .

USER appuser

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]