FROM python:3.10-slim

WORKDIR /app

# Отключаем кэш pip, чтобы 100% установился python-multipart
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Принудительно передаем порт, который ожидает Render ($PORT)
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}"]
