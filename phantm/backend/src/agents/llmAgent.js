import fetch from "node-fetch";

const GROQ_API = "https://api.groq.com/openai/v1/chat/completions";
const MODEL = "llama-3.3-70b-versatile";

const SYSTEM = `You are PHANTM — a senior penetration tester with 15+ years experience. You analyze pre-validated scan data and provide accurate security analysis.

STRICT RULES:
1. NEVER invent CVEs — only reference provided CVE data
2. NEVER hallucinate exploitability — use only provided evidence
3. NEVER inflate severity — missing headers alone max = LOW/MEDIUM
4. EOL software alone is not CRITICAL without specific exploit evidence
5. SMB signing disabled alone = MEDIUM unless domain relay chain confirmed
6. Distinguish: Informational → Hardening → Misconfiguration → Exploitable → Critical Chain
7. Be specific: name exact tools, techniques from provided data only
8. Say explicitly when uncertain`;

export class LLMAgent {
  constructor(scanId, context, apiKey, log) {
    this.context = context;
    this.apiKey = apiKey;
    this.log = log;
  }

  async run() {
    this.log("LLM", "Sending validated findings to Llama 3.3 70B…", "info");
    this.log("LLM", "LLM reasoning on evidence only — no hallucination mode", "info");

    const { domain, findings, attackChains, technologies, reconData } = this.context;

    const prompt = `Analyze this penetration test data for ${domain}. ALL findings are pre-validated by deterministic scanners.

VALIDATED FINDINGS (${findings.length}):
${JSON.stringify(findings.slice(0, 15), null, 2)}

ATTACK CHAINS:
${JSON.stringify(attackChains, null, 2)}

TECHNOLOGIES:
${JSON.stringify(technologies, null, 2)}

INFRASTRUCTURE:
- Open ports: ${(reconData.ports || []).map(p => `${p.port}/${p.service}`).join(", ") || "N/A"}
- Subdomains: ${(reconData.subdomains || []).slice(0, 8).join(", ") || "None"}
- Missing headers: ${(reconData.headers?.missing || []).join(", ") || "None"}

Return ONLY valid JSON (no markdown):
{
  "riskScore": <0-100 realistic>,
  "riskRating": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "executiveSummary": "<3-4 sentences non-technical>",
  "keyRisks": ["<top 5 specific risks with evidence>"],
  "attackNarrative": "<2-3 paragraphs: how attacker moves from initial access to impact>",
  "prioritizedActions": [
    {"priority": 1, "action": "<specific fix>", "effort": "<Low|Medium|High>", "impact": "<risk reduction>"}
  ],
  "complianceImpact": ["<ISO 27001 / NIST / PCI-DSS impacts>"]
}`;

    try {
      const res = await fetch(GROQ_API, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiKey}` },
        body: JSON.stringify({ model: MODEL, max_tokens: 1500, messages: [
          { role: "system", content: SYSTEM },
          { role: "user", content: prompt }
        ]}),
      });

      if (!res.ok) {
        this.log("LLM", `Groq API error ${res.status}`, "error");
        return null;
      }

      const data = await res.json();
      const text = data.choices?.[0]?.message?.content || "{}";
      const clean = text.replace(/```json|```/g, "").trim();
      const result = JSON.parse(clean);
      this.log("LLM", `Analysis complete — Risk: ${result.riskScore}/100 (${result.riskRating})`, "success");
      return result;
    } catch (err) {
      this.log("LLM", `LLM reasoning failed: ${err.message} — using deterministic summary`, "warn");
      return null;
    }
  }
}

export async function groqChat(messages, systemPrompt, apiKey) {
  const res = await fetch(GROQ_API, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      model: MODEL, max_tokens: 1500,
      messages: [
        { role: "system", content: systemPrompt },
        ...messages
      ]
    }),
  });
  if (!res.ok) throw new Error(`Groq error ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content || "";
}
