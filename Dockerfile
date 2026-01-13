FROM python:3.11

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy full backend app folder
COPY app/ ./app/

# Copy dashboard UI correctly
COPY dashboard/ ./dashboard/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
