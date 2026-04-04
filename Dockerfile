FROM python:3.10-slim-bookworm

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (fixed)
RUN mkdir -p /etc/apt/keyrings \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" \
    | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY . .

EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]