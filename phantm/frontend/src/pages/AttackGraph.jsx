import { useEffect, useRef, useState } from "react";
import { scanAPI } from "../lib/api";

const SEV_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#e5c100", LOW: "#00c896", INFO: "#4d9fff" };

function buildGraphData(scanData) {
  const nodes = [];
  const edges = [];

  if (!scanData) return { nodes, edges };

  // Target node
  nodes.push({ id: "target", label: scanData.target, type: "target", color: "#4d9fff" });

  // Finding nodes
  (scanData.findings || []).forEach((f, i) => {
    const id = `finding-${i}`;
    nodes.push({ id, label: f.title?.slice(0, 30) || f.type, type: "finding", severity: f.severity, color: SEV_COLOR[f.severity] || "#666", cvss: f.cvss, port: f.port });
    edges.push({ from: "target", to: id, label: f.port ? `port ${f.port}` : "web" });
  });

  // Chain nodes
  (scanData.attackChains || []).forEach((c, i) => {
    const id = `chain-${i}`;
    nodes.push({ id, label: c.title?.slice(0, 30), type: "chain", color: "#ff3b3b" });
    (scanData.findings || []).slice(0, 2).forEach((_, fi) => {
      edges.push({ from: `finding-${fi}`, to: id, label: "enables", dashed: true });
    });
  });

  return { nodes, edges };
}

export default function AttackGraph({ activeScanId }) {
  const canvasRef = useRef(null);
  const [scanData, setScanData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const animRef = useRef(null);
  const nodesRef = useRef([]);
  const [scans, setScans] = useState([]);
  const [chosenScan, setChosenScan] = useState(activeScanId || "");

  useEffect(() => {
    scanAPI.list().then(r => setScans((r.data || []).filter(s => s.status === "complete"))).catch(() => {});
  }, []);

  useEffect(() => {
    if (chosenScan) {
      setLoading(true);
      scanAPI.get(chosenScan).then(r => { setScanData(r.data); setLoading(false); }).catch(() => setLoading(false));
    }
  }, [chosenScan]);

  useEffect(() => {
    if (!scanData || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    const W = canvas.width = canvas.offsetWidth;
    const H = canvas.height = canvas.offsetHeight;

    const { nodes, edges } = buildGraphData(scanData);

    // Physics layout
    const placed = nodes.map((n, i) => {
      const angle = (i / nodes.length) * Math.PI * 2;
      const r = n.type === "target" ? 0 : n.type === "chain" ? 180 : 280;
      return { ...n, x: W / 2 + Math.cos(angle) * r, y: H / 2 + Math.sin(angle) * r, vx: 0, vy: 0 };
    });
    nodesRef.current = placed;

    let frame = 0;

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      // Background grid
      ctx.strokeStyle = "rgba(30,45,66,0.4)";
      ctx.lineWidth = 1;
      for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
      for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

      // Edges
      edges.forEach(e => {
        const from = placed.find(n => n.id === e.from);
        const to = placed.find(n => n.id === e.to);
        if (!from || !to) return;
        ctx.save();
        if (e.dashed) ctx.setLineDash([4, 4]);
        ctx.strokeStyle = e.dashed ? "rgba(255,59,59,0.4)" : "rgba(77,159,255,0.3)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.restore();

        // Arrow
        const dx = to.x - from.x, dy = to.y - from.y;
        const len = Math.sqrt(dx * dx + dy * dy);
        if (len > 0) {
          const nx = dx / len, ny = dy / len;
          const ax = to.x - nx * 18, ay = to.y - ny * 18;
          ctx.save();
          ctx.translate(ax, ay);
          ctx.rotate(Math.atan2(dy, dx));
          ctx.fillStyle = e.dashed ? "rgba(255,59,59,0.6)" : "rgba(77,159,255,0.6)";
          ctx.beginPath();
          ctx.moveTo(0, 0); ctx.lineTo(-8, -4); ctx.lineTo(-8, 4);
          ctx.closePath(); ctx.fill();
          ctx.restore();
        }
      });

      // Nodes
      placed.forEach(n => {
        const pulse = n.type === "chain" ? Math.sin(frame * 0.05) * 3 : 0;
        const r = (n.type === "target" ? 22 : n.type === "chain" ? 18 : 14) + pulse;

        // Glow
        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 2);
        grd.addColorStop(0, n.color + "44");
        grd.addColorStop(1, "transparent");
        ctx.beginPath(); ctx.arc(n.x, n.y, r * 2, 0, Math.PI * 2);
        ctx.fillStyle = grd; ctx.fill();

        // Node circle
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = n.color + "22";
        ctx.strokeStyle = n.color;
        ctx.lineWidth = n.type === "target" ? 2.5 : 1.5;
        ctx.fill(); ctx.stroke();

        // Label
        ctx.fillStyle = n.color;
        ctx.font = `${n.type === "target" ? "600" : "400"} 10px JetBrains Mono, monospace`;
        ctx.textAlign = "center";
        ctx.fillText(n.label?.slice(0, 20) || "", n.x, n.y + r + 14);

        if (n.cvss) {
          ctx.fillStyle = "rgba(255,255,255,0.6)";
          ctx.font = "9px JetBrains Mono, monospace";
          ctx.fillText(`CVSS ${n.cvss}`, n.x, n.y + r + 24);
        }
      });

      frame++;
      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [scanData]);

  const handleClick = (e) => {
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    const hit = nodesRef.current.find(n => Math.hypot(n.x - mx, n.y - my) < 24);
    setSelected(hit || null);
  };

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">ATTACK GRAPH</h1><p className="page-sub">Visual attack path analysis · click nodes to inspect</p></div>
      </div>

      <div className="form-group" style={{ marginBottom: 16 }}>
        <label className="form-label">SELECT SCAN</label>
        <select className="form-input mono" value={chosenScan} onChange={e => setChosenScan(e.target.value)}>
          <option value="">— select a completed scan —</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.target} ({new Date(s.created_at).toLocaleDateString()})</option>)}
        </select>
      </div>

      {!chosenScan && (
        <div className="empty-state card"><div className="empty-icon">▲</div><div className="empty-title">NO SCAN SELECTED</div><div className="empty-desc muted">Select a completed scan above</div></div>
      )}

      {chosenScan && (
        <div className="graph-layout">
          <div className="card graph-canvas-wrap">
            {loading && <div className="muted mono" style={{ padding: 20, fontSize: 12 }}>Loading scan data…</div>}
            <canvas ref={canvasRef} className="graph-canvas" onClick={handleClick} style={{ width: "100%", height: 480, cursor: "pointer" }} />
            <div className="graph-legend">
              {[["TARGET", "#4d9fff"], ["FINDING", "#ff8c00"], ["ATTACK CHAIN", "#ff3b3b"]].map(([l, c]) => (
                <div key={l} className="legend-item"><span className="legend-dot" style={{ background: c }} /><span className="muted" style={{ fontSize: 10 }}>{l}</span></div>
              ))}
            </div>
          </div>

          {selected && (
            <div className="card node-detail">
              <div className="card-title">NODE DETAIL</div>
              <div className="ctx-row"><span className="muted">Type</span><span className="mono" style={{ fontSize: 11 }}>{selected.type?.toUpperCase()}</span></div>
              <div className="ctx-row"><span className="muted">Label</span><span style={{ fontSize: 12 }}>{selected.label}</span></div>
              {selected.severity && <div className="ctx-row"><span className="muted">Severity</span><span style={{ color: SEV_COLOR[selected.severity] }}>{selected.severity}</span></div>}
              {selected.cvss && <div className="ctx-row"><span className="muted">CVSS</span><span>{selected.cvss}</span></div>}
              {selected.port && <div className="ctx-row"><span className="muted">Port</span><span className="mono">{selected.port}</span></div>}
              <button className="btn-secondary" style={{ marginTop: 12, width: "100%" }} onClick={() => setSelected(null)}>✕ Close</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
