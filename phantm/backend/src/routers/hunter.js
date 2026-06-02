import { Router } from "express";
import { v4 as uuidv4 } from "uuid";
import { dbHelpers } from "../db/sqlite.js";
import { wsManager } from "../services/wsManager.js";

export const hunterRouter = Router();

// Full vulnerability library — all real vulns with detection logic
export const VULN_LIBRARY = {
  "tightvnc-weak-password": {
    id: "VULN-5", label: "TightVNC Using Weak Password",
    cvss: 8.9, severity: "HIGH", ports: ["5900","5901","5902"],
    detect: (text) => (text.includes("5900") || text.includes("5901")) && text.includes("open"),
    evidence: "VNC port open — weak/default password likely",
    remediation: "Set strong VNC password, restrict access by IP, consider VPN",
    cve: "CVE-2019-8260", mitre: ["T1021.005","T1110"]
  },
  "default-credentials": {
    id: "VULN-7", label: "Default Credentials",
    cvss: 8.8, severity: "HIGH", ports: ["21","22","23","80","443","8080","8443"],
    detect: (text) => text.includes("open") && (text.includes("ftp") || text.includes("telnet") || text.includes("http")),
    evidence: "Service exposed — default credentials possible",
    remediation: "Change all default credentials immediately, enforce password policy",
    cve: null, mitre: ["T1078","T1110.001"]
  },
  "smbv1-enabled": {
    id: "VULN-9", label: "Server Message Block (SMB) Protocol Version 1 Enabled",
    cvss: 7.0, severity: "HIGH", ports: ["445","139"],
    detect: (text) => (text.includes("445") || text.includes("139")) && text.includes("open"),
    evidence: "SMB port open — SMBv1 may be enabled (MS17-010/EternalBlue risk)",
    remediation: "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
    cve: "CVE-2017-0144", mitre: ["T1210","T1486"]
  },
  "null-session-enumeration": {
    id: "VULN-12", label: "Anonymous RPC / Null Session Enumeration via SAMR",
    cvss: 5.5, severity: "MEDIUM", ports: ["445","139","135"],
    detect: (text) => (text.includes("445") || text.includes("135")) && text.includes("open"),
    evidence: "RPC/SMB ports open — null session enumeration possible",
    remediation: "Restrict anonymous access via GPO: Network access: Do not allow anonymous enumeration of SAM accounts",
    cve: null, mitre: ["T1046","T1087"]
  },
  "ftp-anonymous": {
    id: "VULN-14", label: "FTP Anonymous Login",
    cvss: 3.7, severity: "LOW", ports: ["21"],
    detect: (text) => text.includes("21/tcp") && text.includes("open"),
    evidence: "FTP service on port 21 — anonymous login may be enabled",
    remediation: "Disable anonymous FTP, require authentication, consider SFTP instead",
    cve: null, mitre: ["T1005","T1083"]
  },
  "smb-signing-disabled": {
    id: "VULN-16", label: "Message Signing is Not Required on the SMB Server",
    cvss: 4.5, severity: "MEDIUM", ports: ["445"],
    detect: (text) => text.includes("445/tcp") && text.includes("open"),
    evidence: "SMB port 445 open — signing not enforced allows NTLM relay attacks",
    remediation: "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true",
    cve: null, mitre: ["T1557.001","T1021.002"]
  },
  "deprecated-ssl-tls": {
    id: "VULN-17", label: "Deprecated SSL/TLS Versions Detected",
    cvss: 5.0, severity: "MEDIUM", ports: ["443","8443","993","995","465"],
    detect: (text) => (text.includes("443") || text.includes("8443")) && text.includes("open"),
    evidence: "HTTPS port open — TLS 1.0/1.1 or SSLv3 may be enabled",
    remediation: "Disable TLS 1.0, TLS 1.1, SSLv2, SSLv3. Enable only TLS 1.2 and 1.3",
    cve: "CVE-2014-3566", mitre: ["T1040"]
  },
  "sweet32": {
    id: "VULN-18", label: "Sweet32 Vulnerability (Birthday Attack on 3DES/Blowfish)",
    cvss: 5.3, severity: "MEDIUM", ports: ["443","8443"],
    detect: (text) => (text.includes("443") || text.includes("8443")) && text.includes("open"),
    evidence: "HTTPS service open — may support 3DES cipher suites vulnerable to Sweet32",
    remediation: "Disable 3DES and RC4 cipher suites. Use AES-GCM ciphers only",
    cve: "CVE-2016-2183", mitre: ["T1040"]
  },
  "eol-windows": {
    id: "VULN-20", label: "End Of Life Microsoft Windows Operating System",
    cvss: 10.0, severity: "CRITICAL", ports: ["445","139","3389"],
    detect: (text) => (text.includes("445") || text.includes("3389")) && text.includes("open"),
    evidence: "Windows services detected — OS may be end-of-life (no security patches)",
    remediation: "Upgrade to supported Windows version immediately. Isolate system until patched",
    cve: null, mitre: ["T1068","T1210"]
  },
  "snmp-default-community": {
    id: "VULN-29", label: "SNMP Agent Default Community Name (public/private)",
    cvss: 5.3, severity: "MEDIUM", ports: ["161","162"],
    detect: (text) => text.includes("161/udp") || text.includes("161/tcp") || text.includes("161") && text.includes("open"),
    evidence: "SNMP port 161 open — default community strings 'public'/'private' likely accepted",
    remediation: "Change SNMP community strings, upgrade to SNMPv3 with auth+encryption",
    cve: null, mitre: ["T1046","T1082"]
  },
  "expired-ssl-cert": {
    id: "VULN-32", label: "Expired SSL Certificate",
    cvss: 6.7, severity: "MEDIUM", ports: ["443","8443","993"],
    detect: (text) => (text.includes("443") || text.includes("8443")) && text.includes("open"),
    evidence: "HTTPS port open — certificate may be expired or self-signed",
    remediation: "Renew SSL certificate via CA. Implement auto-renewal with Let's Encrypt",
    cve: null, mitre: ["T1040"]
  },
  "php-info-disclosure": {
    id: "VULN-35", label: "PHP Info Disclosure",
    cvss: 7.0, severity: "HIGH", ports: ["80","443","8080","8443"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp")) && text.includes("open"),
    evidence: "Web service open — phpinfo() or PHP error disclosure may be accessible",
    remediation: "Disable phpinfo(), set display_errors=Off in php.ini, hide X-Powered-By header",
    cve: null, mitre: ["T1592","T1083"]
  },
  "smb-anonymous-share": {
    id: "VULN-38", label: "Unauthenticated SMB Share with Read/Write Access",
    cvss: 8.0, severity: "HIGH", ports: ["445","139"],
    detect: (text) => (text.includes("445") || text.includes("139")) && text.includes("open"),
    evidence: "SMB ports open — anonymous share access with read/write possible",
    remediation: "Remove anonymous share permissions, require authentication for all SMB shares",
    cve: null, mitre: ["T1039","T1005"]
  },
  "queuejumper-rce": {
    id: "VULN-40", label: "Microsoft Message Queuing RCE (QueueJumper)",
    cvss: 8.1, severity: "HIGH", ports: ["1801"],
    detect: (text) => text.includes("1801") && text.includes("open"),
    evidence: "MSMQ port 1801 open — QueueJumper RCE vulnerability possible",
    remediation: "Patch MS KB5023766. Disable MSMQ if not required. Block port 1801 at firewall",
    cve: "CVE-2023-21554", mitre: ["T1190","T1059"]
  },
  "mssql-eol": {
    id: "VULN-43", label: "Microsoft SQL Server Unsupported Version (EOL)",
    cvss: 10.0, severity: "CRITICAL", ports: ["1433","1434"],
    detect: (text) => (text.includes("1433") || text.includes("1434")) && text.includes("open"),
    evidence: "MSSQL port 1433/1434 open — version may be end-of-life and unpatched",
    remediation: "Upgrade to supported SQL Server version. Apply all security patches immediately",
    cve: null, mitre: ["T1190","T1078"]
  },
  "rdp-no-nla": {
    id: "VULN-48", label: "Terminal Services Doesn't Use Network Level Authentication (NLA)",
    cvss: 5.0, severity: "MEDIUM", ports: ["3389"],
    detect: (text) => text.includes("3389") && text.includes("open"),
    evidence: "RDP port 3389 open — NLA may not be enforced, pre-auth attack surface",
    remediation: "Enable NLA via GPO: Require NLA for remote connections. Block 3389 at perimeter",
    cve: null, mitre: ["T1021.001","T1133"]
  },
  "ssh-terrapin": {
    id: "VULN-50", label: "SSH Terrapin Prefix Truncation Weakness",
    cvss: 5.0, severity: "MEDIUM", ports: ["22"],
    detect: (text) => text.includes("22/tcp") && text.includes("open"),
    evidence: "SSH port 22 open — Terrapin attack (CVE-2023-48795) may apply to older OpenSSH",
    remediation: "Upgrade OpenSSH to 9.6+. Disable CBC cipher modes and ETM MAC algorithms",
    cve: "CVE-2023-48795", mitre: ["T1040","T1557"]
  },
  "filezilla-vuln": {
    id: "VULN-85", label: "FileZilla FTPd 0.9.41 Vulnerabilities",
    cvss: 4.0, severity: "LOW", ports: ["21"],
    detect: (text) => text.includes("21/tcp") && text.includes("open"),
    evidence: "FTP service detected — may be vulnerable FileZilla version 0.9.41",
    remediation: "Upgrade FileZilla Server to latest version. Consider SFTP/FTPS only",
    cve: null, mitre: ["T1005"]
  },
  "mercury-mail": {
    id: "VULN-87", label: "Mercury/32 Mail Server Multiple Vulnerabilities",
    cvss: 5.0, severity: "MEDIUM", ports: ["25","110","143"],
    detect: (text) => (text.includes("25/tcp") || text.includes("110/tcp") || text.includes("143/tcp")) && text.includes("open"),
    evidence: "Mail service port open — may be running vulnerable Mercury/32 mail server",
    remediation: "Upgrade Mercury/32 or migrate to supported mail server (Postfix/Exchange)",
    cve: null, mitre: ["T1566","T1071"]
  },
  "jquery-xss": {
    id: "VULN-90", label: "jQuery 1.2 < 3.5.0 Multiple XSS Vulnerabilities",
    cvss: 5.0, severity: "MEDIUM", ports: ["80","443","8080"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp")) && text.includes("open"),
    evidence: "Web service open — may use vulnerable jQuery < 3.5.0",
    remediation: "Upgrade jQuery to 3.7.0+. Implement Content Security Policy header",
    cve: "CVE-2020-11022", mitre: ["T1190","T1059.007"]
  },
  "ipmi-hash-disclosure": {
    id: "VULN-94", label: "IPMI v2.0 Password Hash Disclosure",
    cvss: 7.0, severity: "HIGH", ports: ["623"],
    detect: (text) => text.includes("623") && text.includes("open"),
    evidence: "IPMI port 623 open — IPMI v2.0 RAKP allows unauthenticated hash retrieval",
    remediation: "Disable IPMI if possible. Use complex passwords. Isolate BMC to management VLAN",
    cve: "CVE-2013-4786", mitre: ["T1552","T1110"]
  },
  "yealink-eol": {
    id: "VULN-96", label: "Yealink SIP-T42S VoIP Phone — End of Life",
    cvss: 7.0, severity: "HIGH", ports: ["80","443","5060","5061"],
    detect: (text) => (text.includes("5060") || text.includes("5061")) && text.includes("open"),
    evidence: "SIP/VoIP port open — may be EOL Yealink device without security patches",
    remediation: "Replace EOL VoIP hardware. Isolate to VLAN, disable web management if unused",
    cve: null, mitre: ["T1190","T1078"]
  },
  "hp-ilo-outdated": {
    id: "VULN-98", label: "HP iLO Web Interface v1.30 Insecure/Outdated",
    cvss: 3.0, severity: "LOW", ports: ["443","17988","17990"],
    detect: (text) => (text.includes("17988") || text.includes("17990") || text.includes("443")) && text.includes("open"),
    evidence: "iLO management port open — may be outdated HP iLO firmware",
    remediation: "Update HP iLO firmware to latest. Restrict iLO access to management network only",
    cve: null, mitre: ["T1190","T1078"]
  },
  "apache-2-4-x-vulns": {
    id: "VULN-100", label: "Apache 2.4.x < 2.4.46 Multiple Vulnerabilities",
    cvss: 3.0, severity: "LOW", ports: ["80","443","8080","8443"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp")) && text.includes("open"),
    evidence: "Web service open — may be running vulnerable Apache < 2.4.46",
    remediation: "Upgrade Apache to 2.4.57+. Enable mod_security WAF",
    cve: "CVE-2020-11984", mitre: ["T1190"]
  },
  "php-eol": {
    id: "VULN-102", label: "PHP Unsupported Version Detection — End of Life",
    cvss: 9.0, severity: "CRITICAL", ports: ["80","443","8080"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp")) && text.includes("open"),
    evidence: "Web service open — may expose EOL PHP version (5.x/7.x < 7.4)",
    remediation: "Upgrade to PHP 8.2+. EOL PHP has unpatched RCE vulnerabilities",
    cve: "CVE-2019-11043", mitre: ["T1190","T1059"]
  },
  "mysql-eol": {
    id: "VULN-108", label: "MySQL 5.7.40 — End of Life",
    cvss: 9.0, severity: "CRITICAL", ports: ["3306"],
    detect: (text) => text.includes("3306") && text.includes("open"),
    evidence: "MySQL port 3306 open — may be EOL version 5.7 without security patches",
    remediation: "Upgrade to MySQL 8.0+. Restrict port 3306 to localhost/app servers only",
    cve: null, mitre: ["T1190","T1078"]
  },
  "php-multiple-vulns": {
    id: "VULN-109", label: "PHP Multiple Critical Vulnerabilities",
    cvss: 9.7, severity: "CRITICAL", ports: ["80","443","8080"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp")) && text.includes("open"),
    evidence: "Web service open — PHP may have multiple RCE/memory corruption vulnerabilities",
    remediation: "Upgrade PHP immediately to 8.2+. Review CVE list for affected version",
    cve: "CVE-2022-31625", mitre: ["T1190","T1059"]
  },
  "flexera-privesc": {
    id: "VULN-112", label: "Flexera FlexNet Publisher < 11.19.6 Privilege Escalation",
    cvss: 7.0, severity: "HIGH", ports: ["27000","27001","27002"],
    detect: (text) => (text.includes("27000") || text.includes("27001")) && text.includes("open"),
    evidence: "FlexNet license manager port open — privilege escalation vulnerability possible",
    remediation: "Upgrade FlexNet Publisher to 11.19.6+",
    cve: "CVE-2021-3474", mitre: ["T1068","T1543"]
  },
  "apache-struts-rce": {
    id: "VULN-114", label: "Apache Struts 2 Remote Code Execution",
    cvss: 6.8, severity: "MEDIUM", ports: ["80","443","8080","8443"],
    detect: (text) => (text.includes("80/tcp") || text.includes("443/tcp") || text.includes("8080")) && text.includes("open"),
    evidence: "Web service open — may be Apache Struts 2 with known RCE vulnerabilities",
    remediation: "Upgrade Apache Struts to 6.3.0+. Apply all security patches immediately",
    cve: "CVE-2017-5638", mitre: ["T1190","T1059"]
  },
};

// Get all vuln types for API
hunterRouter.get("/vulntypes", (req, res) => {
  const types = Object.entries(VULN_LIBRARY).map(([id, v]) => ({
    id, label: v.label, cvss: v.cvss, severity: v.severity, vulnId: v.id, cve: v.cve || null,
  }));
  res.json(types);
});

// Start a hunt
hunterRouter.post("/", async (req, res) => {
  try {
    const { targets, vulnType, apiKey, mode = "single" } = req.body;
    // mode: "single" = one vuln type, "all" = check all vulns
    if (!targets?.length) return res.status(400).json({ error: "targets required" });
    if (mode === "single" && !vulnType) return res.status(400).json({ error: "vulnType required for single mode" });

    const huntId = uuidv4();
    const label = mode === "all" ? "ALL VULNERABILITIES" : VULN_LIBRARY[vulnType]?.label || vulnType;
    await dbHelpers.insertScan({
      id: huntId, target: targets.join(",").slice(0, 500), status: "running",
      scan_type: `hunt:${mode}`, created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(), findings_count: 0, risk_score: 0, summary: null
    });

    if (mode === "all") {
      runFullHunt(huntId, targets).catch(console.error);
    } else {
      runSingleHunt(huntId, targets, vulnType).catch(console.error);
    }

    res.json({ huntId, status: "running", targets: targets.length, mode, label });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get hunt results
hunterRouter.get("/:id", async (req, res) => {
  try {
    const scan = await dbHelpers.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: "Hunt not found" });
    const summary = scan.summary ? JSON.parse(scan.summary) : null;
    res.json({ ...scan, results: summary });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── SINGLE VULN HUNT ─────────────────────────────────────────────────
async function runSingleHunt(huntId, targets, vulnType) {
  const vuln = VULN_LIBRARY[vulnType];
  if (!vuln) { await dbHelpers.updateScan(huntId, { status: "error" }); return; }

  const fetch = (await import("node-fetch")).default;
  const vulnerable = [];
  const checked = [];

  wsManager.log(huntId, "HUNTER", `Hunting: ${vuln.label} [${vuln.id}]`, "sys");
  wsManager.log(huntId, "HUNTER", `Targets: ${targets.length} | CVSS: ${vuln.cvss} | Severity: ${vuln.severity}`, "sys");
  wsManager.log(huntId, "HUNTER", `Checking ports: ${vuln.ports.join(", ")}`, "info");

  for (const target of targets.slice(0, 50)) {
    wsManager.log(huntId, "HUNTER", `Scanning ${target}…`, "info");
    try {
      const res = await fetch(`https://api.hackertarget.com/nmap/?q=${target}`, { timeout: 12000 });
      if (res.ok) {
        const text = await res.text();
        if (!text.includes("error") && !text.includes("API count")) {
          const isVuln = vuln.detect(text);
          checked.push({ target, scanned: true });
          if (isVuln) {
            wsManager.log(huntId, "HUNTER", `⚠ VULNERABLE: ${target} — ${vuln.label}`, "error");
            vulnerable.push({
              target, vulnType, vulnId: vuln.id, label: vuln.label,
              cvss: vuln.cvss, severity: vuln.severity,
              evidence: vuln.evidence, remediation: vuln.remediation,
              cve: vuln.cve, confidence: "MEDIUM",
              mitre: vuln.mitre,
            });
          } else {
            wsManager.log(huntId, "HUNTER", `✓ ${target} — not vulnerable`, "success");
          }
        } else {
          wsManager.log(huntId, "HUNTER", `${target} — API rate limited`, "warn");
          checked.push({ target, scanned: false, reason: "rate-limited" });
        }
      }
    } catch (e) {
      wsManager.log(huntId, "HUNTER", `${target} — timeout/error`, "warn");
      checked.push({ target, scanned: false, reason: "timeout" });
    }
    await new Promise(r => setTimeout(r, 500));
  }

  const summary = { vulnerable, checked, total: targets.length, mode: "single", vulnType };
  await dbHelpers.updateScan(huntId, { status: "complete", findings_count: vulnerable.length, summary: JSON.stringify(summary) });
  wsManager.complete(huntId, summary);
  wsManager.log(huntId, "HUNTER", `━━━ HUNT COMPLETE: ${vulnerable.length}/${targets.length} vulnerable ━━━`, "sys");
}

// ── FULL AUTO HUNT — all vulns ────────────────────────────────────────
async function runFullHunt(huntId, targets) {
  const fetch = (await import("node-fetch")).default;
  const allVulnTypes = Object.keys(VULN_LIBRARY);
  
  // Results: target -> list of vulns found
  const targetResults = {};
  const allVulnerable = [];

  wsManager.log(huntId, "HUNTER", `AUTO HUNT: checking ${allVulnTypes.length} vulnerability types across ${targets.length} targets`, "sys");

  for (const target of targets.slice(0, 20)) {
    wsManager.log(huntId, "HUNTER", `─── Scanning ${target} ───`, "info");
    targetResults[target] = { target, vulns: [], portScan: null };

    try {
      const res = await fetch(`https://api.hackertarget.com/nmap/?q=${target}`, { timeout: 15000 });
      if (res.ok) {
        const text = await res.text();
        if (!text.includes("error") && !text.includes("API count")) {
          targetResults[target].portScan = text;
          wsManager.log(huntId, "HUNTER", `Port scan complete for ${target}`, "success");

          // Check all vulns against this port scan result
          for (const [vulnType, vuln] of Object.entries(VULN_LIBRARY)) {
            if (vuln.detect(text)) {
              wsManager.log(huntId, "HUNTER", `  ⚠ ${target} → ${vuln.label} [CVSS ${vuln.cvss}]`, "error");
              const found = {
                target, vulnType, vulnId: vuln.id, label: vuln.label,
                cvss: vuln.cvss, severity: vuln.severity,
                evidence: vuln.evidence, remediation: vuln.remediation,
                cve: vuln.cve, confidence: "MEDIUM", mitre: vuln.mitre,
              };
              targetResults[target].vulns.push(found);
              allVulnerable.push(found);
            }
          }

          const count = targetResults[target].vulns.length;
          if (count === 0) wsManager.log(huntId, "HUNTER", `  ✓ ${target} — no vulnerabilities detected`, "success");
          else wsManager.log(huntId, "HUNTER", `  ${target}: ${count} potential vulnerabilities`, "warn");

        } else {
          wsManager.log(huntId, "HUNTER", `${target} — rate limited, skipping`, "warn");
        }
      }
    } catch {
      wsManager.log(huntId, "HUNTER", `${target} — timeout`, "warn");
    }
    await new Promise(r => setTimeout(r, 800));
  }

  // Sort by risk
  allVulnerable.sort((a, b) => b.cvss - a.cvss);

  const summary = {
    mode: "all",
    vulnerable: allVulnerable,
    byTarget: Object.values(targetResults),
    total: targets.length,
    totalVulnFindings: allVulnerable.length,
    critical: allVulnerable.filter(v => v.severity === "CRITICAL").length,
    high: allVulnerable.filter(v => v.severity === "HIGH").length,
    medium: allVulnerable.filter(v => v.severity === "MEDIUM").length,
    low: allVulnerable.filter(v => v.severity === "LOW").length,
  };

  await dbHelpers.updateScan(huntId, {
    status: "complete",
    findings_count: allVulnerable.length,
    summary: JSON.stringify(summary)
  });

  wsManager.complete(huntId, summary);
  wsManager.log(huntId, "HUNTER", `━━━ AUTO HUNT COMPLETE: ${allVulnerable.length} findings across ${targets.length} targets ━━━`, "sys");
}
