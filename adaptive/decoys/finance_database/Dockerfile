FROM database-db-honeypot:latest

USER root

COPY app.py /app/app.py

RUN chown honeypot:honeypot /app/app.py

USER honeypot

EXPOSE 15432

CMD ["python", "/app/app.py"]
