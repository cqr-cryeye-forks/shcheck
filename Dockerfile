FROM python:3.13-slim
WORKDIR /app
COPY . .
ENTRYPOINT ["python3", "main.py"]
