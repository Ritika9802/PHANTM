import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useKey } from "../lib/KeyContext";
import { useScanWS } from "../hooks/useScanWS";

const DEPTHS = [
  { id: "quick", label: "QUICK", desc: "Top 100 ports" },
  { id: "standard", label: "STANDARD", desc: "Top 1000 ports" },
  { id: "deep", label: "DEEP", desc: "All ports" },
]

function StatusBadge({ reachable }) {
  return (
    <span className={`scan-status-badge ${reachable ? "complete" : "error"}`}>
      {reachable ? "REACHABLE" : "UNREACHABLE"}
    </span>
  );
}

function ClassificationBadge({ classification }) {
  const label = classification === "private" ? "PRIVATE" : classification === "public" ? "PUBLIC" : "UNKNOWN";
  const color = classification === "private" ? "#00c896" : classification === "public" ? "#4d9fff" : "#9ca3af";

  return (
    <span style={{ fontFamily: "monospace", fontSize: 10, padding: "2px 8px", borderRadius: 2, background: `${color}22`, color, border: `1px solid ${color}44` }}>
      {label}
    </span>
  );
}

function PortBadge({ port }) {
  const color = port.protocol === "udp" ? "#4d9fff" : "#ff8c00";
  return (
    <span style={{ fontFamily: "monospace", fontSize: 10, padding: "2px 8px", borderRadius: 2, background: `${color}22`, color, border: `1px solid ${color}44` }}>
      {port.port}/{port.protocol}
    </span>
  );
}

function formatModeLabel(mode) {
  return mode === "quick" ? "Quick" : mode === "deep" ? "Deep" : "Standard";
}

export default function Hunter() {
  const { apiKey } = useKey();
  const [targets, setTargets] = useState("");
  const [mode, setMode] = useState("standard");
  const [huntId, setHuntId] = useState(null);
  const [results, setResults] = useState(null);
  const [running, setRunning] = useState(false);
  const [activeTab, setActiveTab] = useState("targets");
  const logsRef = useRef(null);
  const { logs, complete } = useScanWS(huntId);

  useEffect(() => {
    if (complete) {
      setResults(complete);
      setRunning(false);
    }
  }, [complete]);

  useEffect(() => {
    logsRef.current?.scrollTo(0, logsRef.current.scrollHeight);
  }, [logs]);

  useEffect(() => {
    if (!huntId || complete) return;

    let active = true;
    let timer = null;
    const poll = async () => {
      try {
        const res = await axios.get(`/api/hunter/${huntId}`);
        if (!active) return;

        const current = res.data?.results || null;
        if (current) {
          setResults(current);
          if (res.data?.status === "complete" || res.data?.status === "error") {
            setRunning(false);
            if (timer) clearInterval(timer);
            return;
          }
        }
      } catch {}
    };

    poll();
    timer = setInterval(poll, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [huntId, complete]);

  const run = async () => {
    const tgts = targets.split(/[\n,\s]+/).map(t => t.trim()).filter(Boolean);
    if (!tgts.length) return;

    setRunning(true);
    setResults(null);

    try {
      const res = await axios.post("/api/hunter/", { targets: tgts, mode, apiKey });
      setHuntId(res.data.huntId);
    } catch (e) {
      setRunning(false);
      alert("Backend error: " + (e.response?.data?.error || e.message));
    }
  };

  const summary = results?.targets ? results : results?.results || {};
  const targetResults = summary.targets || [];
  const totalOpenPorts = summary.totalOpenPorts || targetResults.reduce((count, item) => count + (item.openPorts?.length || 0), 0);
  const flatPorts = targetResults.flatMap(item => (item.openPorts || []).map(port => ({ ...port, target: item.target })));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">HOST SCANNER</h1>
          <p className="page-sub">Ping first, then nmap -sV for open ports, services, and versions</p>
        </div>
        {results && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <div className="model-badge">{formatModeLabel(summary.mode)} MODE</div>
            <div className="model-badge" style={{ borderColor: "rgba(0,200,150,0.3)", color: "#00c896", background: "rgba(0,200,150,0.05)" }}>{summary.reachable || 0} REACHABLE</div>
            <div className="model-badge" style={{ borderColor: "rgba(255,59,59,0.3)", color: "#ff3b3b", background: "rgba(255,59,59,0.05)" }}>{summary.unreachable || 0} UNREACHABLE</div>
          </div>
        )}
      </div>

      <div className="hunter-layout">
        <div className="hunter-left">
          <div className="card">
            <div className="card-title">TARGET INPUT</div>
            <div className="form-group">
              <label className="form-label">IPs / HOSTS (one per line, comma, or space)</label>
              <textarea
                className="form-input mono"
                rows={6}
                placeholder={"192.168.1.1\n192.168.1.2\n10.0.0.15"}
                value={targets}
                onChange={e => setTargets(e.target.value)}
                style={{ resize: "vertical", fontSize: 12 }}
              />
              <div className="muted mono" style={{ fontSize: 10, marginTop: 4 }}>
                {targets.split(/[\n,\s]+/).filter(t => t.trim()).length} targets entered
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">NMAP DEPTH</label>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {DEPTHS.map(opt => (
                  <label key={opt.id} className={`radio-option ${mode === opt.id ? "selected" : ""}`} style={{ justifyContent: "flex-start", gap: 10 }}>
                    <input type="radio" checked={mode === opt.id} onChange={() => setMode(opt.id)} />
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 600, letterSpacing: 1 }}>{opt.label}</div>
                      <div className="muted" style={{ fontSize: 10 }}>{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <button className="btn-primary full-width" onClick={run} disabled={running || !targets.trim()}>
              {running ? "⟳ SCANNING…" : "◈ RUN HOST SCAN"}
            </button>
          </div>
        </div>

        <div className="hunter-right">
          <div className="card terminal-box">
            <div className="terminal-header">
              <span className="term-dot red" /><span className="term-dot amber" /><span className="term-dot green" />
              <span className="terminal-title">SCAN OUTPUT</span>
              {running && <span style={{ marginLeft: "auto", fontFamily: "monospace", fontSize: 10, color: "var(--amber)", animation: "blink 1s infinite" }}>● SCANNING</span>}
            </div>
            <div className="terminal-body scan-terminal" ref={logsRef} style={{ maxHeight: 240 }}>
              {logs.length === 0 && <div className="term-line muted">Enter targets and click RUN HOST SCAN…</div>}
              {logs.map((l, i) => (
                <div key={i} className={`term-line log-${l.type}`}>
                  <span className="term-tag">[{l.agent}]</span>
                  <span className="term-msg">{l.message}</span>
                </div>
              ))}
            </div>
          </div>

          {results && (
            <div className="card" style={{ marginTop: 12 }}>
              <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
                {[
                  { label: "TOTAL TARGETS", val: summary.total || 0, color: "#4d9fff" },
                  { label: "REACHABLE", val: summary.reachable || 0, color: "#00c896" },
                  { label: "UNREACHABLE", val: summary.unreachable || 0, color: "#ff3b3b" },
                  { label: "OPEN PORTS", val: totalOpenPorts, color: "#ff8c00" },
                ].map(stat => (
                  <div key={stat.label} style={{ background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 3, padding: "10px 14px", minWidth: 100 }}>
                    <div style={{ fontFamily: "monospace", fontSize: 9, color: "var(--text-dim)", letterSpacing: 1, marginBottom: 4 }}>{stat.label}</div>
                    <div style={{ fontFamily: "var(--display)", fontSize: 24, fontWeight: 700, color: stat.color }}>{stat.val}</div>
                  </div>
                ))}
              </div>

              <div className="results-tabs" style={{ marginBottom: 12 }}>
                {[
                  { id: "targets", label: `BY TARGET (${targetResults.length})` },
                  { id: "ports", label: `OPEN PORTS (${flatPorts.length})` },
                ].map(t => (
                  <button key={t.id} className={`tab-btn ${activeTab === t.id ? "active" : ""}`} onClick={() => setActiveTab(t.id)}>{t.label}</button>
                ))}
              </div>

              {activeTab === "targets" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {targetResults.length === 0 && <div className="muted mono" style={{ fontSize: 12, padding: 12 }}>No results yet</div>}
                  {targetResults.map((item, index) => (
                    <div key={index} style={{ background: "var(--bg2)", border: `1px solid ${item.reachable ? "rgba(0,200,150,0.25)" : "rgba(255,59,59,0.25)"}`, borderRadius: 4, padding: 14 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "monospace", fontSize: 13, color: "var(--steel)" }}>{item.target}</span>
                        <ClassificationBadge classification={item.classification} />
                        <StatusBadge reachable={item.reachable} />
                        {item.scanMethod && <span className="muted mono" style={{ fontSize: 10 }}>{item.scanMethod}</span>}
                        <span className="muted mono" style={{ fontSize: 11, marginLeft: "auto" }}>{item.openPorts?.length || 0} open port{(item.openPorts?.length || 0) !== 1 ? "s" : ""}</span>
                      </div>

                      {!item.reachable && <div className="muted mono" style={{ fontSize: 11 }}>Host unreachable, nmap was skipped.</div>}

                      {item.reachable && (item.openPorts?.length || 0) === 0 && <div className="muted mono" style={{ fontSize: 11 }}>No open ports found.</div>}

                      {item.openPorts?.length > 0 && (
                        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                          {item.openPorts.map((port, portIndex) => (
                            <div key={portIndex} style={{ display: "grid", gridTemplateColumns: "auto auto 1fr", gap: 10, alignItems: "center", padding: "6px 0", borderTop: "1px solid var(--border)" }}>
                              <PortBadge port={port} />
                              <span className="muted mono" style={{ fontSize: 10 }}>{port.service}</span>
                              <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text)" }}>{port.version || "No version detected"}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === "ports" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {flatPorts.length === 0 && <div className="muted mono" style={{ fontSize: 12, padding: 12 }}>No open ports to show</div>}
                  {flatPorts.map((port, index) => (
                    <div key={index} style={{ background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 3, padding: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "monospace", fontSize: 13, color: "var(--steel)" }}>{port.target}</span>
                        <PortBadge port={port} />
                        <span className="muted mono" style={{ fontSize: 10 }}>{port.service}</span>
                      </div>
                      <div style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text)" }}>{port.version || "No version detected"}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}