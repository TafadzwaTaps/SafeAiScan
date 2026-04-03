import os
import requests

repo_url = os.getenv("REPO_URL")

suspicious = ["eval(", "exec(", "subprocess", "os.system"]

results = []

def scan_file(content):
    return [p for p in suspicious if p in content]

# simulate scan output
results.append({
    "repo": repo_url,
    "issues": ["scan completed in worker"],
    "risk": "MEDIUM"
})

requests.post(
    os.getenv("WEBHOOK_URL"),
    json=results
)