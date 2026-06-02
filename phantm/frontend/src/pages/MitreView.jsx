import { useEffect, useState } from "react";
import { scanAPI } from "../lib/api";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact"
];

const TACTIC_COLOR = {
  "Reconnaissance": "#4d9fff", "Initial Access": "#ff8c00", "Execution": "#ff3b3b",
  "Persistence": "#e5c100", "Privilege Escalation": "#ff3b3b", "Credential Access": "#ff8c00",
  "Discovery": "#4d9fff", "Lateral Movement": "#ff8c00", "Collection": "#e5c100",
  "Exfiltration": "#ff3b3b", "Impact": "#ff3b3b",
};

export default function MitreView({ activeScanId }) {
  const [scans, setScans] = useState([]);
  const [chosenScan, setChosenScan] = useState(activeScanId || "");
  const [scanData, setScanData] = useState(null);
  const [view, setView] = useState("matrix"); // matrix | list

  useEffect(() => {
    scanAPI.list().then(r => setScans((r.data || []).filter(s => s.status === "complete"))).catch(() => {});
  }, []);

  useEffect(() => {
    if (chosenScan) scanAPI.get(chosenScan).then(r => setScanData(r.data)).catch(() => {});
  }, [chosenScan]);

  const mitreMatrix = scanData?.summary ? {} : {};

  // Build matrix from findings
  const FINDING_ATTACK = {
    "sql-injection": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }, { id: "T1005", name: "Data from Local System", tactic: "Collection" }],
    "xss-stored": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
    "rce": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }, { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }, { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" }],
    "lfi": [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }, { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" }],
    "ssrf": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }, { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" }],
    "smb-signing-disabled": [{ id: "T1557.001", name: "LLMNR/NBT-NS Poisoning", tactic: "Credential Access" }, { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" }],
    "smbv1-enabled": [{ id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" }, { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" }],
    "rdp-exposed": [{ id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" }, { id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    "default-credentials": [{ id: "T1078", name: "Valid Accounts", tactic: "Initial Access" }],
    "ftp-exposed": [{ id: "T1005", name: "Data from Local System", tactic: "Collection" }],
    "missing-spf": [{ id: "T1566", name: "Phishing", tactic: "Initial Access" }],
    "missing-dmarc": [{ id: "T1566", name: "Phishing", tactic: "Initial Access" }],
    "mongodb-exposed": [{ id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" }],
    "redis-exposed": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
    "server-header-disclosure": [{ id: "T1592", name: "Gather Victim Host Info", tactic: "Reconnaissance" }],
    "telnet-exposed": [{ id: "T1040", name: "Network Sniffing", tactic: "Credential Access" }],
    "cve-finding": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  };

  const matrix = {};
  (scanData?.findings || []).forEach(f => {
    const techs = FINDING_ATTACK[f.type] || [];
    techs.forEach(t => {
      if (!matrix[t.tactic]) matrix[t.tactic] = [];
      if (!matrix[t.tactic].find(x => x.id === t.id))
        matrix[t.tactic].push({ ...t, finding: f.title, severity: f.severity });
    });
  });

  const coveredTactics = Object.keys(matrix);

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">MITRE ATT&CK</h1><p className="page-sub">Tactic & technique coverage from scan findings</p></div>
        <div className="tab-group">
          {["matrix", "list"].map(v => <button key={v} className={`tab-btn ${view === v ? "active" : ""}`} onClick={() => setView(v)}>{v.toUpperCase()}</button>)}
        </div>
      </div>

      <div className="form-group" style={{ marginBottom: 16 }}>
        <label className="form-label">SELECT SCAN</label>
        <select className="form-input mono" value={chosenScan} onChange={e => setChosenScan(e.target.value)}>
          <option value="">— select a completed scan —</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.target} ({new Date(s.created_at).toLocaleDateString()})</option>)}
        </select>
      </div>

      {coveredTactics.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-title">COVERAGE SUMMARY</div>
          <div className="mitre-coverage-bar">
            {TACTIC_ORDER.map(t => (
              <div key={t} className={`coverage-cell ${matrix[t] ? "covered" : "empty"}`} title={t}
                style={{ background: matrix[t] ? (TACTIC_COLOR[t] || "#ff8c00") + "33" : "transparent", borderColor: matrix[t] ? (TACTIC_COLOR[t] || "#ff8c00") + "66" : "var(--border)" }}>
                <div className="coverage-count" style={{ color: matrix[t] ? (TACTIC_COLOR[t] || "#ff8c00") : "var(--text-faint)" }}>{matrix[t]?.length || 0}</div>
                <div className="coverage-label muted">{t.replace(" ", "\n")}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {!chosenScan && <div className="empty-state card"><div className="empty-icon">★</div><div className="empty-title">SELECT A SCAN</div><div className="empty-desc muted">Choose a completed scan to view ATT&CK coverage</div></div>}
      {chosenScan && coveredTactics.length === 0 && <div className="empty-state card"><div className="empty-icon">★</div><div className="empty-title">NO TECHNIQUES MAPPED</div><div className="empty-desc muted">No findings matched to ATT&CK techniques</div></div>}

      {view === "matrix" && coveredTactics.length > 0 && (
        <div className="mitre-matrix-grid">
          {TACTIC_ORDER.filter(t => matrix[t]).map(tactic => (
            <div key={tactic} className="mitre-tactic-col">
              <div className="mitre-tactic-header" style={{ borderBottomColor: TACTIC_COLOR[tactic] || "#ff8c00", color: TACTIC_COLOR[tactic] || "#ff8c00" }}>{tactic}</div>
              {matrix[tactic].map((t, i) => (
                <div key={i} className="mitre-tech-cell" title={t.finding}>
                  <div className="mitre-tech-id">{t.id}</div>
                  <div className="mitre-tech-name">{t.name}</div>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {view === "list" && coveredTactics.length > 0 && (
        <div className="mitre-list">
          {TACTIC_ORDER.filter(t => matrix[t]).map(tactic => (
            <div key={tactic} className="card" style={{ marginBottom: 12 }}>
              <div className="card-title" style={{ color: TACTIC_COLOR[tactic] || "#ff8c00" }}>{tactic} ({matrix[tactic].length})</div>
              {matrix[tactic].map((t, i) => (
                <div key={i} className="mitre-technique">
                  <span className="mitre-id">{t.id}</span>
                  <span className="mitre-name">{t.name}</span>
                  <span className="muted mitre-finding">{t.finding}</span>
                  <a href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer" className="mitre-link">↗</a>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
