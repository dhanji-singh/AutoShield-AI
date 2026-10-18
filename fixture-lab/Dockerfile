FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home labuser
COPY --chown=labuser:labuser app.py .
USER labuser
EXPOSE 8090
CMD ["python", "app.py"]
