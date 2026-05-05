FROM python:3.12-slim

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
COPY pipeline/requirements.txt ./pipeline/requirements.txt
RUN pip install --no-cache-dir -r pipeline/requirements.txt -r backend/requirements.txt

COPY pipeline/ ./pipeline/
COPY scripts/run_pipeline_full_parquet.py ./scripts/run_pipeline_full_parquet.py

# Aligné sur ECS : uvicorn src.app.main:app  →  PYTHONPATH=/app et package src sous /app/src/
COPY backend/src/ /app/src/

ENV PYTHONPATH=/app/src:/app
ENV DETECTIONS_JSON_PATH=/app/detections.json

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=10s --retries=5 --start-period=90s \
 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=8).read()"

# Même cible que la task ECS (sh -c ... uvicorn src.app.main:app)
CMD ["uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
