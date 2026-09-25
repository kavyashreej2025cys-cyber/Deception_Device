FROM python:3.11-slim

RUN groupadd -r honeypot && useradd -r -g honeypot honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 5432

CMD ["python", "app.py"]
