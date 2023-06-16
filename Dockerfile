FROM python:3.9

COPY ["./TOTP Demo", "/app"]

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

WORKDIR /app

CMD ["uvicorn", "main:app", "--reload", "--ssl-keyfile", "server.key", "--ssl-certfile", "server.cert", "--host", "0.0.0.0"]
