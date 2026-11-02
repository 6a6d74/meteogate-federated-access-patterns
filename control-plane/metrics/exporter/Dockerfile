# The federation's usage exporter: per-service metrics from Keycloak's stored events.
FROM python:3.12.11-slim-bookworm
RUN pip install --no-cache-dir prometheus-client==0.21.1
COPY exporter.py /app/exporter.py
USER 65534
EXPOSE 9100
CMD ["python3", "/app/exporter.py"]
