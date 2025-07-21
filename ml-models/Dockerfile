FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create requirements.txt with the dependencies based on the imports in the code
RUN echo "fastapi>=0.104.1" > requirements.txt && \
    echo "uvicorn[standard]>=0.24.0" >> requirements.txt && \
    echo "numpy>=1.24.0" >> requirements.txt && \
    echo "pandas>=2.0.0" >> requirements.txt && \
    echo "scikit-learn>=1.3.0" >> requirements.txt && \
    echo "joblib>=1.3.0" >> requirements.txt && \
    echo "redis>=5.0.0" >> requirements.txt && \
    echo "aioredis>=2.0.0" >> requirements.txt && \
    echo "prometheus-client>=0.18.0" >> requirements.txt && \
    echo "pydantic>=2.0.0" >> requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/models /app/configs

# Set up a non-root user
RUN useradd -r -s /bin/false appuser
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8082

# Run the ML model server
CMD ["python", "models/model_server.py"]
