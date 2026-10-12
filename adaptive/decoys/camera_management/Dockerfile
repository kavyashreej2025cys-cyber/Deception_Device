FROM iot-iot-honeypot:latest

USER root
COPY app.py /app/app.py
RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app
USER honeypot

EXPOSE 18080
CMD ["python", "/app/app.py"]
