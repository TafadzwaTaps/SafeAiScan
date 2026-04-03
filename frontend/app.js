async function scan() {
  const text = document.getElementById("code").value;

  const res = await analyzeCode(text);

  document.getElementById("result").innerText =
    JSON.stringify(res, null, 2);

  loadUsage();
  loadHistory();
}

async function loadUsage() {
  const data = await getUsage();
  document.getElementById("usage").innerText =
    data.length ? data[data.length - 1].request_count : 0;
}

async function loadHistory() {
  const data = await getHistory();

  const list = document.getElementById("history");
  list.innerHTML = "";

  data.slice(0, 5).forEach(item => {
    const li = document.createElement("li");
    li.innerText = `${item.risk} - ${item.score}`;
    list.appendChild(li);
  });
}

async function upgrade(plan) {
  const res = await createCheckout(plan);
  window.location.href = res.checkout_url;
}

function copyKey() {
  navigator.clipboard.writeText(localStorage.getItem("api_key"));
}

async function init() {
  document.getElementById("apiKey").innerText =
    localStorage.getItem("api_key");

  loadUsage();
  loadHistory();
}

init();