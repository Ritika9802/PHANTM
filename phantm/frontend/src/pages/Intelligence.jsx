// Intelligence.jsx
import { useState, useRef, useEffect } from "react";
import { intelAPI, scanAPI } from "../lib/api";
import { useKey } from "../lib/KeyContext";

const PROMPTS = [
  "What is the realistic attack path from initial access to domain compromise?",
  "Which finding has the highest actual exploitability and exact PoC steps?",
  "What would a ransomware group target first in this environment?",
  "Which findings are likely false positives and why?",
  "Write a prioritized 30-60-90 day remediation plan",
  "Map these findings to the Cyber Kill Chain",
  "What MITRE ATT&CK sub-techniques are most relevant?",
  "Explain the business impact for a non-technical executive",
];

function Bubble({ msg }) {
  const isUser = msg.role === "user";
  return (
    <div className={`msg-wrap ${isUser ? "msg-user" : "msg-ai"}`}>
      {!isUser && <div className="msg-avatar ai-avatar">⬡</div>}
      <div className={`msg-bubble ${isUser ? "bubble-user" : "bubble-ai"}`}>
        <pre className="msg-text">{msg.content}</pre>
        {msg.ts && <div className="msg-ts">{msg.ts}</div>}
      </div>
      {isUser && <div className="msg-avatar user-avatar">◈</div>}
    </div>
  );
}

export default function Intelligence({ activeScanId }) {
  const { apiKey } = useKey();
  const [messages, setMessages] = useState([{ role: "assistant", content: "PHANTM AI online — Llama 3.3 70B.\n\nRun a scan first for context-aware analysis, or ask about penetration testing, CVEs, or security methodology.", ts: new Date().toLocaleTimeString() }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    if (activeScanId) {
      scanAPI.get(activeScanId).then(r => {
        setScanData(r.data);
        setMessages(m => [...m, { role: "assistant", content: `Scan context loaded: ${r.data.target}\nRisk: ${r.data.summary?.riskScore || "N/A"}/100 · ${r.data.findings?.length || 0} findings`, ts: new Date().toLocaleTimeString() }]);
      }).catch(() => {});
    }
  }, [activeScanId]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const buildContext = () => scanData ? {
    target: scanData.target, riskScore: scanData.summary?.riskScore,
    findings: scanData.findings?.slice(0, 8),
    attackChains: scanData.attackChains,
    executiveSummary: scanData.summary?.executiveSummary,
  } : null;

  const send = async (text) => {
    const q = (text || input).trim();
    if (!q || loading) return;
    setInput("");
    const userMsg = { role: "user", content: q, ts: new Date().toLocaleTimeString() };
    const history = [...messages, userMsg];
    setMessages(history);
    setLoading(true);
    try {
      const res = await intelAPI.chat(history.filter(m => m.role !== "system").map(m => ({ role: m.role, content: m.content })), buildContext(), apiKey);
      setMessages([...history, { role: "assistant", content: res.data.reply, ts: new Date().toLocaleTimeString() }]);
    } catch (e) {
      setMessages([...history, { role: "assistant", content: `Error: ${e.response?.data?.error || e.message}`, ts: new Date().toLocaleTimeString() }]);
    }
    setLoading(false);
  };

  return (
    <div className="page intel-page">
      <div className="page-header">
        <div><h1 className="page-title">AI ANALYST</h1><p className="page-sub">Context-aware reasoning · Llama 3.3 70B · evidence-based only</p></div>
        {scanData && <div className="context-badge"><span className="ctx-dot" />SCAN LOADED · {scanData.target}</div>}
      </div>
      <div className="intel-layout">
        <div className="quick-prompts card">
          <div className="card-title">ANALYST PROMPTS</div>
          {PROMPTS.map((p, i) => <button key={i} className="quick-btn" onClick={() => send(p)}><span className="quick-arrow">▶</span> {p}</button>)}
          {scanData?.summary && (
            <div className="scan-summary">
              <div className="card-title" style={{ marginTop: 24 }}>CONTEXT</div>
              <div className="ctx-row"><span className="muted">Target</span><span className="mono" style={{ fontSize: 11 }}>{scanData.target}</span></div>
              <div className="ctx-row"><span className="muted">Risk</span><span style={{ color: "#ff8c00" }}>{scanData.summary.riskScore}/100</span></div>
              <div className="ctx-row"><span className="muted">Findings</span><span>{scanData.findings?.length}</span></div>
              <div className="ctx-row"><span className="muted">Chains</span><span style={{ color: scanData.attackChains?.length > 0 ? "#ff3b3b" : "inherit" }}>{scanData.attackChains?.length || 0}</span></div>
            </div>
          )}
        </div>
        <div className="chat-panel card">
          <div className="chat-messages">
            {messages.map((m, i) => <Bubble key={i} msg={m} />)}
            {loading && <div className="msg-wrap msg-ai"><div className="msg-avatar ai-avatar">⬡</div><div className="msg-bubble bubble-ai"><div className="typing-dots"><span /><span /><span /></div></div></div>}
            <div ref={bottomRef} />
          </div>
          <div className="chat-input-bar">
            <input className="chat-input mono" placeholder="Ask about findings, attack paths, exploit techniques…" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()} disabled={loading} />
            <button className="btn-primary send-btn" onClick={() => send()} disabled={loading || !input}>{loading ? "⟳" : "▶"}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
