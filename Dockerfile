FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PALSY_HOST=0.0.0.0 \
    PALSY_PORT=8080 \
    PALSY_STATE_DIR=/var/lib/palsy \
    PALSY_REQUIRE_API_TOKEN=true \
    PALSY_LOG_LEVEL=INFO

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY palsy /app/palsy
COPY config /app/config
RUN pip install --no-cache-dir . && useradd -r -u 10001 palsy && mkdir -p /var/lib/palsy && chown -R palsy:palsy /var/lib/palsy
USER palsy
EXPOSE 8080
CMD ["uvicorn", "palsy.api:app", "--host", "0.0.0.0", "--port", "8080"]
