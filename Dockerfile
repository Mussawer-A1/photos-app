# backend/Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the app
COPY . .

# Run the Flask app from api/_init_.py
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
