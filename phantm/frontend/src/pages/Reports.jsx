import { useEffect, useState } from "react";
import { reportsAPI, intelAPI } from "../lib/api";
import { useKey } from "../lib/KeyContext";

const SEV_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#e5c100", LOW: "#00c896", INFO: "#4d9fff" };

export default function Reports() {
  const { apiKey } = useKey();
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [format, setFormat] = useState("executive");
  const [report, setReport] = useState(null);
  const [generating, setGenerating] = useState(false);

  useEffect(() => { reportsAPI.list().then(r => setScans(r.data || [])).catch(() => {}); }, []);

  const generate = async () => {
    if (!selected) return;
    setGenerating(true); setReport(null);
    try {
      const res = await intelAPI.report(selected.id, format, apiKey);
      setReport(res.data.report);
    } catch (e) {
      setReport(`Error: ${e.response?.data?.error || e.message}`);
    }
    setGenerating(false);
  };

  const download = () => {
    if (!report) return;
    const blob = new Blob([report], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phantm-${format}-${selected?.target}-${Date.now()}.txt`;
    a.click();
  };

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">REPORTS</h1><p className="page-sub">AI-generated pentest reports from validated scan data</p></div>
      </div>

      <div className="reports-layout">
        <div className="report-config card">
          <div className="card-title">SCAN SELECTION</div>
          {scans.length === 0 && <div className="muted mono" style={{ fontSize: 12 }}>No completed scans yet</div>}
          {scans.map(s => {
            const sum = s.summary ? JSON.parse(s.summary) : {};
            return (
              <div key={s.id} className={`scan-row ${selected?.id === s.id ? "selected-row" : ""}`} onClick={() => setSelected(s)} style={{ cursor: "pointer" }}>
                <div className="scan-row-target mono">{s.target}</div>
                <div className="scan-row-meta">
                  {sum.riskScore > 0 && <span style={{ color: sum.riskScore > 70 ? "#ff3b3b" : "#ff8c00", fontSize: 12 }}>{sum.riskScore}/100</span>}
                  <span className="muted" style={{ fontSize: 11 }}>{s.findings_count} findings</span>
                </div>
              </div>
            );
          })}

          {selected && (
            <>
              <div className="card-title" style={{ marginTop: 20 }}>REPORT FORMAT</div>
              {[
                { id: "executive", label: "EXECUTIVE BRIEF", desc: "Business risk for C-suite" },
                { id: "technical", label: "TECHNICAL REPORT", desc: "CVEs, CVSS, PoC, remediation" },
                { id: "compliance", label: "COMPLIANCE REPORT", desc: "ISO 27001, NIST, PCI-DSS" },
              ].map(opt => (
                <label key={opt.id} className={`report-option ${format === opt.id ? "selected" : ""}`}>
                  <input type="radio" name="fmt" value={opt.id} checked={format === opt.id} onChange={() => setFormat(opt.id)} />
                  <div><div className="opt-label">{opt.label}</div><div className="opt-desc muted">{opt.desc}</div></div>
                </label>
              ))}
              <button className="btn-primary full-width" onClick={generate} disabled={generating} style={{ marginTop: 16 }}>
                {generating ? "⟳ GENERATING…" : "⬡ GENERATE REPORT"}
              </button>
            </>
          )}
        </div>

        <div className="report-output card">
          <div className="report-output-header">
            <div className="card-title">REPORT OUTPUT</div>
            {report && <button className="btn-secondary" onClick={download}>⬇ EXPORT TXT</button>}
          </div>
          {!selected && <div className="empty-state-inline muted">Select a scan from the left panel</div>}
          {selected && !report && !generating && <div className="empty-state-inline muted">Select format → Generate Report</div>}
          {generating && <div className="generating-state"><div className="gen-icon pulse-icon">⬡</div><div className="muted">Llama 3.3 composing report from validated findings…</div></div>}
          {report && <pre className="report-text mono">{report}</pre>}
        </div>
      </div>
    </div>
  );
}
