import { BrowserRouter, Routes, Route, NavLink, Navigate } from "react-router-dom";
import { useState } from "react";
import { KeyProvider, useKey } from "./lib/KeyContext";
import KeySetup from "./components/KeySetup";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import Intelligence from "./pages/Intelligence";
import Reports from "./pages/Reports";
import Hunter from "./pages/Hunter";
import AttackGraph from "./pages/AttackGraph";
import MitreView from "./pages/MitreView";

const NAV = [
  { to: "/", label: "DASHBOARD", icon: "⬡" },
  { to: "/scan", label: "SCAN ENGINE", icon: "◈" },
  { to: "/hunter", label: "VULN HUNTER", icon: "⛓" },
  { to: "/intelligence", label: "AI ANALYST", icon: "◉" },
  { to: "/attack-graph", label: "ATTACK GRAPH", icon: "▲" },
  { to: "/mitre", label: "MITRE ATT&CK", icon: "★" },
  { to: "/reports", label: "REPORTS", icon: "◧" },
];

function Layout() {
  const { apiKey, saveKey } = useKey();
  const [activeScan, setActiveScan] = useState(null);

  if (!apiKey) return <KeySetup />;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">⬡</div>
          <div>
            <div className="brand-name">PHANTM</div>
            <div className="brand-sub">AI·VAPT·FRAMEWORK</div>
          </div>
        </div>
        <div className="sidebar-status">
          <span className="status-dot pulse" />
          LLAMA 3.3 · ONLINE
        </div>
        <nav className="sidebar-nav">
          {NAV.map(n => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
              <span className="nav-icon">{n.icon}</span>
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>
        {activeScan && (
          <div className="active-scan-pill">
            <span className="pulse-dot" />
            <span className="mono" style={{ fontSize: 10 }}>Scan active</span>
          </div>
        )}
        <div className="sidebar-footer">
          <div className="footer-line">v2.0.0 · Llama 3.3 70B</div>
          <button className="key-reset-btn" onClick={() => saveKey("")}>⟳ Reset Key</button>
        </div>
      </aside>
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard onNavigate={setActiveScan} />} />
          <Route path="/scan" element={<Scanner onScanStart={setActiveScan} />} />
          <Route path="/hunter" element={<Hunter />} />
          <Route path="/intelligence" element={<Intelligence activeScanId={activeScan} />} />
          <Route path="/attack-graph" element={<AttackGraph activeScanId={activeScan} />} />
          <Route path="/mitre" element={<MitreView activeScanId={activeScan} />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <KeyProvider>
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    </KeyProvider>
  );
}
