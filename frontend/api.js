const BASE_URL = "https://rathious-safeaiscan.hf.space";

function headers() {
  return {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + localStorage.getItem("access_token"),
    "x-api-key": localStorage.getItem("api_key")
  };
}

async function analyzeCode(text) {
  const res = await fetch(`${BASE_URL}/api/analyze`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ text })
  });

  return await res.json();
}

async function getHistory() {
  const res = await fetch(`${BASE_URL}/api/history`, {
    headers: headers()
  });

  return await res.json();
}

async function getUsage() {
  const res = await fetch(`${BASE_URL}/api/usage`, {
    headers: headers()
  });

  return await res.json();
}

async function createCheckout(plan) {
  const res = await fetch(`${BASE_URL}/billing/create-checkout?plan=${plan}`, {
    method: "POST",
    headers: headers()
  });

  return await res.json();
}