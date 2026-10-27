FROM python:3.11-slim

WORKDIR /app

RUN useradd --create-home appuser
USER appuser

COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=appuser:appuser . .

CMD ["python", "app.py"]