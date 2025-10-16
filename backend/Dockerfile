# Backend Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# --- 0️⃣ Install build dependencies for psycopg2 and PostgreSQL client ---
RUN apt-get update && apt-get install -y \
    postgresql-client \
    build-essential \
    libpq-dev \
    gcc \
    python3-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Upgrade pip
RUN pip install --upgrade pip

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Make wait-for-postgres.sh executable
RUN ["chmod", "+x", "./wait-for-postgres.sh"]

# Expose port for Django
EXPOSE 8000

# CMD to start the dev server (can be overridden in docker-compose)
CMD ["./wait-for-postgres.sh", "db", "--", "python", "manage.py", "runserver", "0.0.0.0:8000"]
