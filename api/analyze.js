export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { text } = req.body;

  if (!text || text.trim() === "") {
    return res.status(400).json({ error: "Empty input" });
  }

  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: `You are a cybersecurity expert.

Return JSON:
{
  "risk": "Low | Medium | High",
  "explanation": "",
  "fixes": []
}

Keep it short.`
          },
          {
            role: "user",
            content: text
          }
        ],
        max_tokens: 150,
        temperature: 0.2
      })
    });

    const data = await response.json();

    let result = data.choices?.[0]?.message?.content || "{}";

// 🛡️ Ensure valid JSON
try {
  result = JSON.parse(result);
} catch {
  result = {
    risk: "unknown",
    explanation: result,
    fixes: []
  };
}

    return res.status(200).json({ result });

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}