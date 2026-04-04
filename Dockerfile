FROM python:3.10

WORKDIR /app

# -------------------------------------------------
# SYSTEM DEPENDENCIES (VERY IMPORTANT)
# -------------------------------------------------
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------
# INSTALL TRIVY (CVE SCANNER)
# -------------------------------------------------
RUN apt-get update && apt-get install -y wget gnupg lsb-release

RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy

# -------------------------------------------------
# PYTHON DEPENDENCIES
# -------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------------------------------
# APP CODE
# -------------------------------------------------
COPY . .

EXPOSE 7860

CMD ["sh", "-c", "celery -A tasks.celery worker --loglevel=info & uvicorn app:app --host 0.0.0.0 --port 7860"]