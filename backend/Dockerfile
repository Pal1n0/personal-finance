# Backend Dockerfile for Personal Finance Application
#
# This Dockerfile sets up the Django backend environment with PostgreSQL support
# and includes necessary build dependencies for development and production.

# Use official Python runtime as base image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# --- 0️⃣ Install system dependencies for PostgreSQL and build tools ---
RUN apt-get update && apt-get install -y \
    postgresql-client \      # PostgreSQL client utilities
    build-essential \        # Compiler toolchain
    libpq-dev \              # PostgreSQL development libraries
    gcc \                    # GNU Compiler Collection
    python3-dev \            # Python development headers
    netcat-openbsd \         # Network utility for health checks
    && rm -rf /var/lib/apt/lists/*  # Clean up package lists to reduce image size

# Copy requirements file for dependency installation
COPY requirements.txt .

# Upgrade pip to latest version
RUN pip install --upgrade pip

# Install Python dependencies from requirements file
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend project into container
COPY . .

# Make the database wait script executable
RUN ["chmod", "+x", "./wait-for-postgres.sh"]

# Expose port 8000 for Django development server
EXPOSE 8000

# Default command to start Django development server
# This waits for PostgreSQL to be ready before starting the server
# Can be overridden in docker-compose.yml for different environments
CMD ["./wait-for-postgres.sh", "db", "--", "python", "manage.py", "runserver", "0.0.0.0:8000"]