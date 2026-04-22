FROM python:3.10-slim-bookworm

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN mkdir -p /etc/apt/keyrings \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" \
    | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# FIX: install semgrep separately (not in requirements.txt — needs special handling)
RUN pip install --no-cache-dir semgrep

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY . .

# FIX: rename _env to .env so python-dotenv picks it up automatically
RUN if [ -f _env ]; then cp _env .env; fi

EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
