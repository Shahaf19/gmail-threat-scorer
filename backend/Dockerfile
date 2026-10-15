FROM python:3.11-slim

# Logs go straight to Cloud Run instead of sitting in a buffer; no .pyc clutter in the image.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# An unprivileged user limits what a compromised process could change inside the container.
RUN useradd --no-create-home appuser
USER appuser

# Cloud Run tells the container which port to listen on through $PORT.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}
