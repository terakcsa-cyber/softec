FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.1 requests==2.32.4
COPY app.py .

ENV HOST=0.0.0.0
ENV PORT=5000
EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --retries=12 --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/languages', timeout=3)"

CMD ["python", "app.py"]
