import { useState, useRef, useEffect } from "react";
import axios from "axios";
import { useKey } from "../lib/KeyContext";
import { useScanWS } from "../hooks/useScanWS";

const SEV_COLOR = { CRITICAL: "#ff3b3b", HIGH: "#ff8c00", MEDIUM: "#e5c100", LOW: "#00c896", INFO: "#4d9fff" };
const SEV_BG   = { CRITICAL: "rgba(255,59,59,0.12)", HIGH: "rgba(255,140,0,0.12)", MEDIUM: "rgba(229,193,0,0.12)", LOW: "rgba(0,200,150,0.12)", INFO: "rgba(77,159,255,0.12)" };

// Full vuln library — mirrors backend
const VULN_LIBRARY = [
  { id: "tightvnc-weak-password",    vulnId:"VULN-5",   label:"TightVNC Using Weak Password",                              cvss:8.9,  severity:"HIGH"     },
  { id: "default-credentials",       vulnId:"VULN-7",   label:"Default Credentials",                                       cvss:8.8,  severity:"HIGH"     },
  { id: "smbv1-enabled",             vulnId:"VULN-9",   label:"SMB Protocol Version 1 Enabled",                           cvss:7.0,  severity:"HIGH"     },
  { id: "null-session-enumeration",  vulnId:"VULN-12",  label:"Anonymous RPC / Null Session Enumeration via SAMR",        cvss:5.5,  severity:"MEDIUM"   },
  { id: "ftp-anonymous",             vulnId:"VULN-14",  label:"FTP Anonymous Login",                                       cvss:3.7,  severity:"LOW"      },
  { id: "smb-signing-disabled",      vulnId:"VULN-16",  label:"SMB Message Signing Not Required",                         cvss:4.5,  severity:"MEDIUM"   },
  { id: "deprecated-ssl-tls",        vulnId:"VULN-17",  label:"Deprecated SSL/TLS Versions Detected",                    cvss:5.0,  severity:"MEDIUM"   },
  { id: "sweet32",                   vulnId:"VULN-18",  label:"Sweet32 Birthday Attack (3DES/Blowfish)",                  cvss:5.3,  severity:"MEDIUM"   },
  { id: "eol-windows",               vulnId:"VULN-20",  label:"End Of Life Microsoft Windows OS",                         cvss:10.0, severity:"CRITICAL" },
  { id: "snmp-default-community",    vulnId:"VULN-29",  label:"SNMP Agent Default Community Name",                        cvss:5.3,  severity:"MEDIUM"   },
  { id: "expired-ssl-cert",          vulnId:"VULN-32",  label:"Expired SSL Certificate",                                  cvss:6.7,  severity:"MEDIUM"   },
  { id: "php-info-disclosure",       vulnId:"VULN-35",  label:"PHP Info Disclosure",                                      cvss:7.0,  severity:"HIGH"     },
  { id: "smb-anonymous-share",       vulnId:"VULN-38",  label:"Unauthenticated SMB Share (Read/Write)",                  cvss:8.0,  severity:"HIGH"     },
  { id: "queuejumper-rce",           vulnId:"VULN-40",  label:"Microsoft MSMQ RCE (QueueJumper)",                        cvss:8.1,  severity:"HIGH"     },
  { id: "mssql-eol",                 vulnId:"VULN-43",  label:"Microsoft SQL Server Unsupported Version (EOL)",          cvss:10.0, severity:"CRITICAL" },
  { id: "rdp-no-nla",                vulnId:"VULN-48",  label:"Terminal Services Without NLA",                           cvss:5.0,  severity:"MEDIUM"   },
  { id: "ssh-terrapin",              vulnId:"VULN-50",  label:"SSH Terrapin Prefix Truncation Weakness",                 cvss:5.0,  severity:"MEDIUM"   },
  { id: "filezilla-vuln",            vulnId:"VULN-85",  label:"FileZilla FTPd 0.9.41 Vulnerabilities",                  cvss:4.0,  severity:"LOW"      },
  { id: "mercury-mail",              vulnId:"VULN-87",  label:"Mercury/32 Mail Server Multiple Vulnerabilities",         cvss:5.0,  severity:"MEDIUM"   },
  { id: "jquery-xss",                vulnId:"VULN-90",  label:"jQuery 1.2 < 3.5.0 Multiple XSS",                        cvss:5.0,  severity:"MEDIUM"   },
  { id: "ipmi-hash-disclosure",      vulnId:"VULN-94",  label:"IPMI v2.0 Password Hash Disclosure",                      cvss:7.0,  severity:"HIGH"     },
  { id: "yealink-eol",               vulnId:"VULN-96",  label:"Yealink SIP-T42S VoIP Phone — End of Life",              cvss:7.0,  severity:"HIGH"     },
  { id: "hp-ilo-outdated",           vulnId:"VULN-98",  label:"HP iLO Web Interface Insecure/Outdated",                 cvss:3.0,  severity:"LOW"      },
  { id: "apache-2-4-x-vulns",       vulnId:"VULN-100", label:"Apache 2.4.x < 2.4.46 Multiple Vulnerabilities",         cvss:3.0,  severity:"LOW"      },
  { id: "php-eol",                   vulnId:"VULN-102", label:"PHP Unsupported Version — End of Life",                  cvss:9.0,  severity:"CRITICAL" },
  { id: "mysql-eol",                 vulnId:"VULN-108", label:"MySQL 5.7.40 — End of Life",                             cvss:9.0,  severity:"CRITICAL" },
  { id: "php-multiple-vulns",        vulnId:"VULN-109", label:"PHP Multiple Critical Vulnerabilities",                   cvss:9.7,  severity:"CRITICAL" },
  { id: "flexera-privesc",           vulnId:"VULN-112", label:"Flexera FlexNet Publisher < 11.19.6 Privilege Escalation",cvss:7.0,  severity:"HIGH"     },
  { id: "apache-struts-rce",         vulnId:"VULN-114", label:"Apache Struts 2 Remote Code Execution",                  cvss:6.8,  severity:"MEDIUM"   },
];

function SevBadge({ severity }) {
  return (
    <span style={{
      fontFamily: "monospace", fontSize: 9, padding: "3px 8px", borderRadius: 2,
      letterSpacing: 1, fontWeight: 700,
      background: SEV_BG[severity] || "#33333322",
      color: SEV_COLOR[severity] || "#aaa",
      border: `1px solid ${SEV_COLOR[severity] || "#666"}44`,
    }}>{severity}</span>
  );
}

function CvssBar({ cvss }) {
  const pct = (cvss / 10) * 100;
  const color = cvss >= 9 ? "#ff3b3b" : cvss >= 7 ? "#ff8c00" : cvss >= 4 ? "#e5c100" : "#00c896";
  return (
    <div style={{ display:"flex", alignItems:"center", gap:6 }}>
      <div style={{ flex:1, height:4, background:"var(--bg3)", borderRadius:2, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:color, borderRadius:2 }} />
      </div>
      <span style={{ fontFamily:"monospace", fontSize:10, color, minWidth:28 }}>{cvss}</span>
    </div>
  );
}

export default function Hunter() {
  const { apiKey } = useKey();
  const [targets, setTargets] = useState("");
  const [mode, setMode] = useState("all"); // "all" | "single"
  const [selectedVuln, setSelectedVuln] = useState("smbv1-enabled");
  const [huntId, setHuntId] = useState(null);
  const [results, setResults] = useState(null);
  const [running, setRunning] = useState(false);
  const [activeTab, setActiveTab] = useState("list"); // results tabs
  const [filterSev, setFilterSev] = useState("ALL");
  const [search, setSearch] = useState("");
  const logsRef = useRef(null);
  const { logs, complete } = useScanWS(huntId);

  useEffect(() => {
    if (complete && !results) {
      setResults(complete);
      setRunning(false);
    }
  }, [complete]);

  useEffect(() => {
    logsRef.current?.scrollTo(0, logsRef.current.scrollHeight);
  }, [logs]);

  const run = async () => {
    const tgts = targets.split(/[\n,\s]+/).map(t => t.trim()).filter(Boolean);
    if (!tgts.length) return;
    setRunning(true); setResults(null);
    try {
      const res = await axios.post("/api/hunter/", {
        targets: tgts,
        vulnType: mode === "single" ? selectedVuln : null,
        mode,
        apiKey,
      });
      setHuntId(res.data.huntId);
    } catch (e) {
      setRunning(false);
      alert("Backend error: " + (e.response?.data?.error || e.message));
    }
  };

  // Filter results
  const allVulns = results?.vulnerable || [];
  const filtered = allVulns.filter(v => {
    const sevOk = filterSev === "ALL" || v.severity === filterSev;
    const searchOk = !search || v.label?.toLowerCase().includes(search.toLowerCase()) || v.target?.includes(search);
    return sevOk && searchOk;
  });

  // Group by target for "by target" view
  const byTarget = {};
  allVulns.forEach(v => {
    if (!byTarget[v.target]) byTarget[v.target] = [];
    byTarget[v.target].push(v);
  });

  const critCount = allVulns.filter(v => v.severity === "CRITICAL").length;
  const highCount = allVulns.filter(v => v.severity === "HIGH").length;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">VULNERABILITY HUNTER</h1>
          <p className="page-sub">Mass scan for {VULN_LIBRARY.length} vulnerability types — single or full auto-check</p>
        </div>
        {results && (
          <div style={{ display:"flex", gap:8 }}>
            {critCount > 0 && <div className="model-badge" style={{ borderColor:"#ff3b3b44", color:"#ff3b3b", background:"rgba(255,59,59,0.06)" }}>⚠ {critCount} CRITICAL</div>}
            {highCount > 0 && <div className="model-badge" style={{ borderColor:"#ff8c0044", color:"#ff8c00", background:"rgba(255,140,0,0.06)" }}>▲ {highCount} HIGH</div>}
          </div>
        )}
      </div>

      <div className="hunter-layout">
        {/* ── LEFT CONFIG PANEL ── */}
        <div className="hunter-left">
          {/* Targets */}
          <div className="card">
            <div className="card-title">TARGET INPUT</div>
            <div className="form-group">
              <label className="form-label">IPs / DOMAINS (one per line, comma, or space)</label>
              <textarea
                className="form-input mono"
                rows={5}
                placeholder={"192.168.1.1\n192.168.1.2\n10.0.0.0/24\ntarget.com"}
                value={targets}
                onChange={e => setTargets(e.target.value)}
                style={{ resize:"vertical", fontSize:12 }}
              />
              <div className="muted mono" style={{ fontSize:10, marginTop:4 }}>
                {targets.split(/[\n,\s]+/).filter(t => t.trim()).length} targets entered
              </div>
            </div>

            {/* Mode selection */}
            <div className="form-group">
              <label className="form-label">SCAN MODE</label>
              <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                <label className={`radio-option ${mode === "all" ? "selected" : ""}`} style={{ justifyContent:"flex-start", gap:10 }}>
                  <input type="radio" checked={mode === "all"} onChange={() => setMode("all")} />
                  <div>
                    <div style={{ fontSize:12, fontWeight:600, letterSpacing:1 }}>AUTO — CHECK ALL VULNERABILITIES</div>
                    <div className="muted" style={{ fontSize:10 }}>Scan for all {VULN_LIBRARY.length} vuln types in one run</div>
                  </div>
                </label>
                <label className={`radio-option ${mode === "single" ? "selected" : ""}`} style={{ justifyContent:"flex-start", gap:10 }}>
                  <input type="radio" checked={mode === "single"} onChange={() => setMode("single")} />
                  <div>
                    <div style={{ fontSize:12, fontWeight:600, letterSpacing:1 }}>SINGLE VULNERABILITY CHECK</div>
                    <div className="muted" style={{ fontSize:10 }}>Target one specific vulnerability type</div>
                  </div>
                </label>
              </div>
            </div>

            <button className="btn-primary full-width" onClick={run} disabled={running || !targets.trim()}>
              {running ? "⟳ HUNTING…" : mode === "all" ? "⛓ AUTO SCAN ALL VULNS" : "⛓ HUNT SINGLE VULN"}
            </button>
          </div>

          {/* Vuln selector — only shown in single mode */}
          {mode === "single" && (
            <div className="card" style={{ marginTop:12 }}>
              <div className="card-title">SELECT VULNERABILITY</div>
              <div className="vuln-selector">
                {VULN_LIBRARY.map(v => (
                  <div
                    key={v.id}
                    className={`vuln-select-item ${selectedVuln === v.id ? "selected" : ""}`}
                    onClick={() => setSelectedVuln(v.id)}
                  >
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                      <span className="muted mono" style={{ fontSize:9 }}>{v.vulnId}</span>
                      <SevBadge severity={v.severity} />
                      <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:10, color: v.cvss >= 9 ? "#ff3b3b" : v.cvss >= 7 ? "#ff8c00" : "#e5c100" }}>{v.cvss}</span>
                    </div>
                    <div style={{ fontSize:12, color:"var(--text)", fontFamily:"var(--display)" }}>{v.label}</div>
                    <CvssBar cvss={v.cvss} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* In auto mode, show all vulns as reference */}
          {mode === "all" && (
            <div className="card" style={{ marginTop:12 }}>
              <div className="card-title">CHECKING {VULN_LIBRARY.length} VULNERABILITIES</div>
              <div style={{ maxHeight:300, overflowY:"auto" }}>
                {VULN_LIBRARY.map(v => (
                  <div key={v.id} style={{ display:"flex", alignItems:"center", gap:8, padding:"6px 0", borderBottom:"1px solid var(--border)" }}>
                    <span className="muted mono" style={{ fontSize:9, minWidth:55 }}>{v.vulnId}</span>
                    <SevBadge severity={v.severity} />
                    <span style={{ flex:1, fontSize:11, color:"var(--text)" }}>{v.label}</span>
                    <span style={{ fontFamily:"monospace", fontSize:10, color: v.cvss >= 9 ? "#ff3b3b" : v.cvss >= 7 ? "#ff8c00" : "#e5c100" }}>{v.cvss}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── RIGHT: LOG + RESULTS ── */}
        <div className="hunter-right">
          {/* Live terminal */}
          <div className="card terminal-box">
            <div className="terminal-header">
              <span className="term-dot red" /><span className="term-dot amber" /><span className="term-dot green" />
              <span className="terminal-title">HUNT OUTPUT</span>
              {running && <span style={{ marginLeft:"auto", fontFamily:"monospace", fontSize:10, color:"var(--amber)", animation:"blink 1s infinite" }}>● SCANNING</span>}
            </div>
            <div className="terminal-body scan-terminal" ref={logsRef} style={{ maxHeight:240 }}>
              {logs.length === 0 && <div className="term-line muted">Configure hunt and click START…</div>}
              {logs.map((l, i) => (
                <div key={i} className={`term-line log-${l.type}`}>
                  <span className="term-tag">[{l.agent}]</span>
                  <span className="term-msg">{l.message}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Results */}
          {results && (
            <div className="card" style={{ marginTop:12 }}>
              {/* Summary bar */}
              <div style={{ display:"flex", gap:12, marginBottom:16, flexWrap:"wrap" }}>
                {[
                  { label:"TOTAL FINDINGS", val: allVulns.length, color:"#4d9fff" },
                  { label:"CRITICAL", val: critCount, color:"#ff3b3b" },
                  { label:"HIGH", val: highCount, color:"#ff8c00" },
                  { label:"MEDIUM", val: allVulns.filter(v=>v.severity==="MEDIUM").length, color:"#e5c100" },
                  { label:"LOW", val: allVulns.filter(v=>v.severity==="LOW").length, color:"#00c896" },
                  { label:"TARGETS", val: results.total || 0, color:"var(--text-dim)" },
                ].map(s => (
                  <div key={s.label} style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:3, padding:"10px 14px", minWidth:80 }}>
                    <div style={{ fontFamily:"monospace", fontSize:9, color:"var(--text-dim)", letterSpacing:1, marginBottom:4 }}>{s.label}</div>
                    <div style={{ fontFamily:"var(--display)", fontSize:24, fontWeight:700, color:s.color }}>{s.val}</div>
                  </div>
                ))}
              </div>

              {/* Tabs */}
              <div className="results-tabs" style={{ marginBottom:12 }}>
                {[
                  { id:"list", label:`ALL FINDINGS (${allVulns.length})` },
                  { id:"bytarget", label:`BY TARGET (${Object.keys(byTarget).length})` },
                  { id:"byvuln", label:"BY VULN TYPE" },
                ].map(t => (
                  <button key={t.id} className={`tab-btn ${activeTab===t.id?"active":""}`} onClick={()=>setActiveTab(t.id)}>{t.label}</button>
                ))}
              </div>

              {/* Filter bar */}
              <div style={{ display:"flex", gap:8, marginBottom:12, flexWrap:"wrap" }}>
                <input className="form-input mono" placeholder="Search target or vuln…" value={search} onChange={e=>setSearch(e.target.value)} style={{ flex:1, fontSize:11, padding:"6px 10px" }} />
                {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
                  <button key={s} className={`tab-btn ${filterSev===s?"active":""}`} onClick={()=>setFilterSev(s)} style={{ fontSize:10, padding:"4px 10px" }}>{s}</button>
                ))}
              </div>

              {/* List view */}
              {activeTab === "list" && (
                <div className="vuln-list">
                  {filtered.length === 0 && <div className="muted mono" style={{ fontSize:12, padding:12 }}>No findings match filter</div>}
                  {filtered.map((v, i) => (
                    <div key={i} className="vuln-item" style={{ borderLeft:`3px solid ${SEV_COLOR[v.severity]||"#666"}` }}>
                      <div className="vuln-header">
                        <span className="muted mono" style={{ fontSize:9 }}>{v.vulnId}</span>
                        <SevBadge severity={v.severity} />
                        <span className="vuln-title">{v.label}</span>
                        <span style={{ fontFamily:"monospace", fontSize:11, color: v.cvss>=9?"#ff3b3b":v.cvss>=7?"#ff8c00":"#e5c100" }}>CVSS {v.cvss}</span>
                      </div>
                      <div style={{ display:"flex", gap:16, marginTop:6, flexWrap:"wrap" }}>
                        <div>
                          <div className="muted mono" style={{ fontSize:9, marginBottom:2 }}>TARGET</div>
                          <div className="mono" style={{ fontSize:12, color:"var(--steel)" }}>{v.target}</div>
                        </div>
                        {v.cve && (
                          <div>
                            <div className="muted mono" style={{ fontSize:9, marginBottom:2 }}>CVE</div>
                            <span className="cve-tag">{v.cve}</span>
                          </div>
                        )}
                        <div>
                          <div className="muted mono" style={{ fontSize:9, marginBottom:2 }}>CONFIDENCE</div>
                          <span className="muted" style={{ fontSize:11 }}>{v.confidence}</span>
                        </div>
                      </div>
                      <div className="muted" style={{ fontFamily:"monospace", fontSize:11, marginTop:6 }}>{v.evidence}</div>
                      <div style={{ fontFamily:"monospace", fontSize:11, color:"var(--steel)", marginTop:4 }}>▶ {v.remediation}</div>
                      {v.mitre?.length > 0 && (
                        <div className="muted mono" style={{ fontSize:10, marginTop:4 }}>MITRE: {v.mitre.join(", ")}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* By target view */}
              {activeTab === "bytarget" && (
                <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                  {Object.entries(byTarget).length === 0 && <div className="muted mono" style={{ fontSize:12, padding:12 }}>No vulnerable targets found</div>}
                  {Object.entries(byTarget)
                    .sort((a,b) => b[1].length - a[1].length)
                    .map(([target, vulns]) => {
                      const maxSev = vulns.reduce((m, v) => {
                        const order = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFO:0 };
                        return order[v.severity] > order[m] ? v.severity : m;
                      }, "INFO");
                      return (
                        <div key={target} style={{ background:"var(--bg2)", border:`1px solid ${SEV_COLOR[maxSev]||"#1e2d42"}44`, borderRadius:4, padding:14 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:10 }}>
                            <span style={{ fontFamily:"monospace", fontSize:13, color:"var(--steel)" }}>{target}</span>
                            <SevBadge severity={maxSev} />
                            <span className="muted mono" style={{ fontSize:11, marginLeft:"auto" }}>{vulns.length} finding{vulns.length!==1?"s":""}</span>
                          </div>
                          {vulns.sort((a,b)=>b.cvss-a.cvss).map((v, i) => (
                            <div key={i} style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 0", borderTop:"1px solid var(--border)" }}>
                              <span className="muted mono" style={{ fontSize:9, minWidth:55 }}>{v.vulnId}</span>
                              <SevBadge severity={v.severity} />
                              <span style={{ flex:1, fontSize:12, color:"var(--text)" }}>{v.label}</span>
                              <span style={{ fontFamily:"monospace", fontSize:10, color:v.cvss>=9?"#ff3b3b":v.cvss>=7?"#ff8c00":"#e5c100" }}>{v.cvss}</span>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                </div>
              )}

              {/* By vuln type view */}
              {activeTab === "byvuln" && (
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {(() => {
                    const byType = {};
                    allVulns.forEach(v => {
                      if (!byType[v.vulnId]) byType[v.vulnId] = { label:v.label, severity:v.severity, cvss:v.cvss, targets:[] };
                      byType[v.vulnId].targets.push(v.target);
                    });
                    return Object.entries(byType)
                      .sort((a,b) => b[1].cvss - a[1].cvss)
                      .map(([vulnId, info]) => (
                        <div key={vulnId} style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:3, padding:12 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
                            <span className="muted mono" style={{ fontSize:9 }}>{vulnId}</span>
                            <SevBadge severity={info.severity} />
                            <span style={{ flex:1, fontSize:13, fontWeight:500 }}>{info.label}</span>
                            <span style={{ fontFamily:"monospace", fontSize:11, color:info.cvss>=9?"#ff3b3b":info.cvss>=7?"#ff8c00":"#e5c100" }}>CVSS {info.cvss}</span>
                          </div>
                          <div className="muted mono" style={{ fontSize:10, marginBottom:4 }}>{info.targets.length} AFFECTED TARGET{info.targets.length!==1?"S":""}</div>
                          <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
                            {info.targets.map((t, i) => (
                              <span key={i} style={{ fontFamily:"monospace", fontSize:11, padding:"2px 8px", background:"rgba(77,159,255,0.1)", color:"var(--steel)", border:"1px solid rgba(77,159,255,0.25)", borderRadius:2 }}>{t}</span>
                            ))}
                          </div>
                        </div>
                      ));
                  })()}
                  {allVulns.length === 0 && <div className="muted mono" style={{ fontSize:12, padding:12 }}>No vulnerabilities found</div>}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
