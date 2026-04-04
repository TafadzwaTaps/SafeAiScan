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
RUN wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.0_Linux-64bit.deb \
    && dpkg -i trivy_0.50.0_Linux-64bit.deb

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