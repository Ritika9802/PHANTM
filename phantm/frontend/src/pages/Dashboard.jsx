import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from "recharts";
import { scanAPI } from "../lib/api";

const SEV_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#e5c100", LOW: "#00c896", INFO: "#4d9fff" };

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    scanAPI.list().then(r => { setScans(r.data || []); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const completed = scans.filter(s => s.status === "complete");
  const totalFindings = completed.reduce((a, s) => a + (s.findings_count || 0), 0);
  const avgRisk = completed.length ? Math.round(completed.reduce((a, s) => a + (s.risk_score || 0), 0) / completed.length) : 0;

  const radarData = [
    { axis: "Network", val: 65 }, { axis: "Web App", val: 78 },
    { axis: "API", val: 52 }, { axis: "Cloud", val: 38 },
    { axis: "DNS", val: 71 }, { axis: "Auth", val: 60 },
  ];

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">DASHBOARD</h1><p className="page-sub">Real-time threat intelligence overview</p></div>
        <button className="btn-primary" onClick={() => navigate("/scan")}>◈ NEW SCAN</button>
      </div>

      <div className="stat-grid">
        {[
          { label: "TOTAL SCANS", val: scans.length, color: "#4d9fff" },
          { label: "FINDINGS", val: totalFindings, color: "#ff8c00" },
          { label: "ACTIVE SCANS", val: scans.filter(s => s.status === "running").length, color: "#e5c100" },
          { label: "AVG RISK SCORE", val: avgRisk, color: avgRisk > 70 ? "#ff3b3b" : "#ff8c00" },
        ].map(s => (
          <div className="stat-card" key={s.label}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-val" style={{ color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      <div className="dash-grid">
        <div className="card">
          <div className="card-title">ATTACK SURFACE COVERAGE</div>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#1e2d42" />
              <PolarAngleAxis dataKey="axis" tick={{ fill: "#7a8fa6", fontSize: 11, fontFamily: "monospace" }} />
              <Radar dataKey="val" stroke="#ff8c00" fill="#ff8c00" fillOpacity={0.12} strokeWidth={1.5} dot={{ r: 3, fill: "#ff8c00" }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">RECENT SCANS</div>
          {loading && <div className="muted mono" style={{ fontSize: 12 }}>Loading…</div>}
          {!loading && scans.length === 0 && (
            <div className="empty-state-inline">
              <div className="muted mono" style={{ fontSize: 12 }}>No scans yet — <span className="amber link" onClick={() => navigate("/scan")} style={{ cursor: "pointer" }}>start your first scan</span></div>
            </div>
          )}
          {scans.slice(0, 6).map(s => (
            <div key={s.id} className="scan-row" onClick={() => navigate("/scan")}>
              <div className="scan-row-target mono">{s.target}</div>
              <div className="scan-row-meta">
                <span className={`scan-status-badge ${s.status}`}>{s.status.toUpperCase()}</span>
                {s.risk_score > 0 && <span style={{ color: s.risk_score > 70 ? "#ff3b3b" : "#ff8c00", fontSize: 12 }}>{s.risk_score}/100</span>}
                <span className="muted" style={{ fontSize: 11 }}>{new Date(s.created_at).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="card card-wide">
          <div className="card-title">BACKEND STATUS</div>
          <BackendStatus />
        </div>
      </div>
    </div>
  );
}

function BackendStatus() {
  const [status, setStatus] = useState(null);
  useEffect(() => {
    fetch("/api/health").then(r => r.json()).then(setStatus).catch(() => setStatus({ error: true }));
  }, []);
  return (
    <div className="backend-status">
      {!status && <div className="muted mono" style={{ fontSize: 12 }}>Checking backend…</div>}
      {status?.error && (
        <div className="status-error">
          <div className="status-err-title">⚠ Backend Not Running</div>
          <div className="mono muted" style={{ fontSize: 11 }}>Start it: cd backend && npm run dev</div>
        </div>
      )}
      {status && !status.error && (
        <div className="status-ok">
          <span className="status-dot pulse" style={{ display: "inline-block" }} />
          <span className="mono" style={{ fontSize: 12 }}>Backend online · {status.version} · {status.model}</span>
        </div>
      )}
    </div>
  );
}
