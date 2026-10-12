FROM web-web-honeypot:latest

USER root

COPY --chown=honeypot:honeypot app.py /app/app.py
COPY --chown=honeypot:honeypot templates/ /app/templates/

RUN mkdir -p /app/logs && chown honeypot:honeypot /app/logs

USER honeypot

EXPOSE 15000

CMD ["python", "/app/app.py"]
