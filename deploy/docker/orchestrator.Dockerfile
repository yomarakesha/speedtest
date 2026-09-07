FROM python:3.12-slim
WORKDIR /app
COPY orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY orchestrator/app ./app
ENV AUDIT_SVC_URL=http://audit-svc:8081
ENV SCAN_SVC_URL=http://scan-svc:8082
ENV ORCHESTRATOR_DB=/data/orchestrator.db
ENV FINDINGS_LOG_PATH=/var/log/netsec-orchestrator/findings.jsonl
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
