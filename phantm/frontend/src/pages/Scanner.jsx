import { useState, useRef, useEffect } from "react";
import { scanAPI } from "../lib/api";
import { useKey } from "../lib/KeyContext";
import { useScanWS } from "../hooks/useScanWS";

const SEV_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#e5c100", LOW: "#00c896", INFO: "#4d9fff" };
const STAGES = [
  { id: "recon", label: "Recon & DNS", icon: "◈", desc: "crt.sh · HackerTarget DNS · headers" },
  { id: "fingerprint", label: "Fingerprint", icon: "◉", desc: "Version extraction from banners" },
  { id: "cve", label: "CVE Correlation", icon: "⬡", desc: "NVD · CISA KEV · version matching" },
  { id: "validate", label: "Validation", icon: "◧", desc: "FP reduction · precondition checks" },
  { id: "severity", label: "CVSS Calibration", icon: "▲", desc: "Deterministic CVSS v3.1 scoring" },
  { id: "chains", label: "Attack Chains", icon: "⛓", desc: "Multi-finding correlation" },
  { id: "mitre", label: "MITRE Mapping", icon: "★", desc: "ATT&CK TTP tagging" },
  { id: "llm", label: "LLM Reasoning", icon: "⬡", desc: "Llama 3 70B — evidence-based only" },
];

export default function Scanner({ onScanStart }) {
  const { apiKey } = useKey();
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("standard");
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [loadingResults, setLoadingResults] = useState(false);
  const [activeTab, setActiveTab] = useState("findings");
  const [backendDown, setBackendDown] = useState(false);
  const logsRef = useRef(null);

  const { logs, stages, findings: wsFindings, complete } = useScanWS(scanId);

  const startScan = async () => {
    if (!target.trim()) return;
    try {
      const res = await scanAPI.create(target.trim(), scanType, apiKey);
      const id = res.data.scanId;
      setScanId(id);
      setScanData(null);
      onScanStart?.(id);
      setBackendDown(false);
    } catch (err) {
      if (err.code === "ERR_NETWORK") setBackendDown(true);
    }
  };

  const loadResults = async () => {
    if (!scanId || loadingResults) return;
    setLoadingResults(true);
    try {
      const res = await scanAPI.get(scanId);
      setScanData(res.data);
    } catch {}
    finally {
      setLoadingResults(false);
    }
  };

  useEffect(() => {
    if (complete && !scanData) loadResults();
  }, [complete, scanData, scanId]);

  const allFindings = scanData?.findings || wsFindings;
  const chains = scanData?.attackChains || [];
  const summary = scanData?.summary || complete;

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">SCAN ENGINE</h1><p className="page-sub">8-stage deterministic pipeline · CVE-validated · Llama 3 70B</p></div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
          {summary?.scanMode === "host" && (
            <div className="model-badge">{String(summary.classification || "host").toUpperCase()} · HOST SCAN</div>
          )}
          <div className="model-badge">⬡ LLAMA 3 · 70B · GROQ</div>
        </div>
      </div>

      {backendDown && (
        <div className="alert-banner">
          ⚠ Backend not running — open a new terminal and run: <span className="mono">cd backend && npm install && npm run dev</span>
        </div>
      )}

      <div className="scan-layout-v2">
        <div className="scan-left">
          <div className="card">
            <div className="card-title">TARGET</div>
            <input className="form-input mono" placeholder="domain.com or 192.168.1.1" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && startScan()} />
            <div className="form-group" style={{ marginTop: 12 }}>
              <div className="radio-group">
                {["quick","standard","deep"].map(t => (
                  <label key={t} className={`radio-option ${scanType === t ? "selected" : ""}`}>
                    <input type="radio" checked={scanType === t} onChange={() => setScanType(t)} />
                    {t.toUpperCase()}
                  </label>
                ))}
              </div>
            </div>
            <button className="btn-primary full-width" onClick={startScan} disabled={!target || !!scanId && !complete}>
              {scanId && !complete ? "⟳ SCANNING…" : "◈ EXECUTE SCAN"}
            </button>
          </div>

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">PIPELINE</div>
            {STAGES.map(s => (
              <div className="module-row" key={s.id}>
                <span className="module-icon">{s.icon}</span>
                <div style={{ flex: 1 }}>
                  <div className="module-name">{s.label}</div>
                  <div className="module-desc muted">{s.desc}</div>
                </div>
                <span className={`stage-badge ${stages[s.id] || "idle"}`}>
                  {stages[s.id] === "running" ? "●" : stages[s.id] === "done" ? "✓" : "○"}
                </span>
              </div>
            ))}
          </div>

          {summary && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="card-title">SUMMARY</div>
              {[["CRITICAL", summary.critical, "#ff3b3b"], ["HIGH", summary.high, "#ff8c00"],
                ["MEDIUM", summary.medium, "#e5c100"], ["LOW", summary.low, "#00c896"],
                ["ATTACK CHAINS", summary.attackChains, "#ff3b3b"], ["CISA KEV", summary.cisaKevCount, "#ff3b3b"]
              ].map(([l, v, c]) => (
                <div className="ctx-row" key={l}>
                  <span className="muted mono" style={{ fontSize: 10 }}>{l}</span>
                  <span style={{ color: v > 0 ? c : "var(--text-dim)", fontWeight: 600 }}>{v ?? 0}</span>
                </div>
              ))}
              {summary.riskScore > 0 && (
                <div className="risk-banner" style={{ marginTop: 12, borderColor: summary.riskScore > 70 ? "#ff3b3b" : "#ff8c00" }}>
                  <div className="risk-score" style={{ color: summary.riskScore > 70 ? "#ff3b3b" : "#ff8c00" }}>{summary.riskScore}</div>
                  <div><div className="risk-label">{summary.riskRating}</div><div className="muted" style={{ fontSize: 10 }}>Risk Score / 100</div></div>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="scan-right">
          <div className="card terminal-box">
            <div className="terminal-header">
              <span className="term-dot red" /><span className="term-dot amber" /><span className="term-dot green" />
              <span className="terminal-title">PIPELINE OUTPUT</span>
            </div>
            <div className="terminal-body scan-terminal" ref={logsRef}>
              {logs.length === 0 && <div className="term-line muted">Awaiting target…</div>}
              {logs.map((l, i) => (
                <div key={i} className={`term-line log-${l.type}`}>
                  <span className="term-tag">[{l.agent}]</span>
                  <span className="term-msg">{l.message}</span>
                </div>
              ))}
              {scanId && !complete && <div className="term-cursor">▋</div>}
            </div>
          </div>

          {(allFindings.length > 0 || chains.length > 0) && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="results-tabs">
                {["findings","chains"].map(tab => (
                  <button key={tab} className={`tab-btn ${activeTab === tab ? "active" : ""}`} onClick={() => setActiveTab(tab)}>
                    {tab.toUpperCase()} {tab === "findings" ? `(${allFindings.length})` : `(${chains.length})`}
                  </button>
                ))}
              </div>

              {activeTab === "findings" && (
                <div className="vuln-list" style={{ marginTop: 12 }}>
                  {allFindings.sort((a, b) => (b.cvss || 0) - (a.cvss || 0)).map((f, i) => (
                    <div className="vuln-item" key={i}>
                      <div className="vuln-header">
                        <span className="sev-badge" style={{ background: (SEV_COLOR[f.severity]||"#666")+"22", color: SEV_COLOR[f.severity]||"#aaa", border:`1px solid ${(SEV_COLOR[f.severity]||"#666")}44` }}>{f.severity}</span>
                        <span className="vuln-title">{f.title}</span>
                        {f.cvss && <span className="vuln-cvss muted">CVSS {f.cvss}</span>}
                        {f.cveId && <span className="cve-tag">{f.cveId}</span>}
                        {(f.inCisaKev || f.in_cisa_kev) && <span className="kev-tag">⚠ KEV</span>}
                      </div>
                      {f.evidence && <div className="vuln-desc muted">{f.evidence}</div>}
                      {f.validationNote && <div className="calibration-note muted">{f.validationNote}</div>}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "chains" && (
                <div className="chains-list" style={{ marginTop: 12 }}>
                  {chains.length === 0 && <div className="muted mono" style={{ fontSize: 12, padding: 8 }}>No attack chains identified</div>}
                  {chains.map((c, i) => (
                    <div className="chain-item" key={i}>
                      <div className="chain-header">
                        <span className="sev-badge" style={{ background: "#ff3b3b22", color: "#ff3b3b", border: "1px solid #ff3b3b44" }}>CRITICAL</span>
                        <span className="chain-title">{c.title}</span>
                        <span className="muted" style={{ fontSize: 11 }}>{c.likelihood}</span>
                      </div>
                      {(typeof c.steps === "string" ? JSON.parse(c.steps) : c.steps || []).map((step, j) => (
                        <div key={j} className="chain-step"><span className="step-arrow">→</span><span>{step}</span></div>
                      ))}
                      <div className="chain-impact muted" style={{ marginTop: 6 }}>Impact: <span style={{ color: "#ff8c00" }}>{c.impact}</span></div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {summary?.attackNarrative && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="card-title">AI ATTACK NARRATIVE</div>
              <p className="narrative-text">{summary.attackNarrative}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
