import { useState } from "react";
import { useKey } from "../lib/KeyContext";

export default function KeySetup() {
  const { saveKey } = useKey();
  const [val, setVal] = useState("");
  const [err, setErr] = useState("");

  const submit = () => {
    const k = val.trim();
    if (!k.startsWith("gsk_") || k.length < 30) { setErr("Key must start with gsk_ — get it free at console.groq.com"); return; }
    saveKey(k);
  };

  return (
    <div className="key-overlay">
      <div className="key-modal">
        <div className="key-icon">⬡</div>
        <div className="key-title">PHANTM REQUIRES A FREE GROQ API KEY</div>
        <div className="key-sub">Powered by <span className="amber">Llama 3.3 70B</span> via Groq — 100% free, no credit card</div>
        <div className="key-steps">
          <div className="key-step"><span className="step-num">01</span><span>Go to <a href="https://console.groq.com" target="_blank" rel="noreferrer" className="link">console.groq.com</a></span></div>
          <div className="key-step"><span className="step-num">02</span><span>Sign up free → API Keys → Create Key</span></div>
          <div className="key-step"><span className="step-num">03</span><span>Paste key below — stored locally in your browser</span></div>
        </div>
        <input className="form-input mono key-input" placeholder="gsk_xxxxxxxxxxxxxxxxxxxxxxxx" value={val} onChange={e => setVal(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} type="password" autoFocus />
        {err && <div className="key-err">{err}</div>}
        <button className="btn-primary full-width" onClick={submit} disabled={!val}>▶ CONNECT & LAUNCH</button>
        <div className="key-note muted">Key never leaves your browser — sent directly to Groq API</div>
      </div>
    </div>
  );
}
