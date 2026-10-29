FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home appuser
USER appuser

COPY --chown=appuser:appuser requirements.txt .
RUN python -m pip install --no-cache-dir --user --no-compile -r requirements.txt

COPY --chown=appuser:appuser . .

CMD ["python", "app.py"]