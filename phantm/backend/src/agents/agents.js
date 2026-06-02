// FingerprintAgent
export class FingerprintAgent {
  constructor(scanId, reconData, log) {
    this.reconData = reconData;
    this.log = log;
  }
  async run() {
    this.log("FINGERPRINT", "Extracting technology versions…", "info");
    const techs = [];
    const { headers, ports } = this.reconData;

    if (headers?.server) {
      const s = headers.server;
      techs.push({ name: "Web Server", value: s, source: "Server Header" });
      const apache = s.match(/Apache\/(\d+\.\d+\.?\d*)/i);
      if (apache) { techs.push({ name: "Apache", version: apache[1], source: "Server Header" }); this.log("FINGERPRINT", `Apache ${apache[1]} detected`, "data"); }
      const nginx = s.match(/nginx\/(\d+\.\d+\.?\d*)/i);
      if (nginx) { techs.push({ name: "Nginx", version: nginx[1], source: "Server Header" }); this.log("FINGERPRINT", `Nginx ${nginx[1]} detected`, "data"); }
      const iis = s.match(/Microsoft-IIS\/(\d+\.\d+)/i);
      if (iis) { techs.push({ name: "IIS", version: iis[1], source: "Server Header" }); this.log("FINGERPRINT", `IIS ${iis[1]} detected`, "data"); }
    }
    if (headers?.poweredBy) {
      const pb = headers.poweredBy;
      const php = pb.match(/PHP\/(\d+\.\d+\.?\d*)/i);
      if (php) { techs.push({ name: "PHP", version: php[1], source: "X-Powered-By" }); this.log("FINGERPRINT", `PHP ${php[1]} detected`, "data"); }
    }
    (ports || []).forEach(p => {
      const ssh = p.version?.match(/OpenSSH[_\s](\d+\.\d+p?\d*)/i);
      if (ssh) { techs.push({ name: "OpenSSH", version: ssh[1], port: p.port, source: "Port scan" }); this.log("FINGERPRINT", `OpenSSH ${ssh[1]} on port ${p.port}`, "data"); }
    });

    this.log("FINGERPRINT", `Identified ${techs.length} technologies/versions`, "success");
    return techs;
  }
}

// CVEAgent
const KNOWN_VERSION_CVES = {
  "apache/2.4.49": ["CVE-2021-41773","CVE-2021-42013"],
  "apache/2.4.50": ["CVE-2021-42013"],
  "php/7.4": ["CVE-2021-21703","CVE-2022-31625"],
  "php/7.2": ["CVE-2019-11043"],
  "php/5.6": ["CVE-2019-11043"],
  "jquery/1": ["CVE-2019-11358","CVE-2020-11022"],
  "jquery/2": ["CVE-2019-11358","CVE-2020-11022"],
  "log4j/2.0": ["CVE-2021-44228"],
  "log4j/2.14": ["CVE-2021-44228"],
  "log4j/2.15": ["CVE-2021-45046"],
  "openssh/9.5": ["CVE-2023-51385","CVE-2023-48795"],
  "openssh/9.6": ["CVE-2023-48795"],
};

const EXPLOIT_DB = {
  "CVE-2021-41773": { available: true, type: "Path Traversal / RCE", complexity: "LOW" },
  "CVE-2021-44228": { available: true, type: "RCE (Log4Shell)", complexity: "LOW" },
  "CVE-2019-11043": { available: true, type: "RCE (PHP-FPM)", complexity: "LOW" },
  "CVE-2023-48795": { available: true, type: "Protocol Downgrade (Terrapin)", complexity: "HIGH" },
  "CVE-2021-21703": { available: true, type: "Privilege Escalation", complexity: "MEDIUM" },
};

const CISA_KEV_KNOWN = new Set(["CVE-2021-41773","CVE-2021-44228","CVE-2019-11043","CVE-2021-42013"]);

export class CVEAgent {
  constructor(scanId, technologies, log) {
    this.technologies = technologies;
    this.log = log;
  }
  async run() {
    this.log("CVE", "Correlating versions with CVE database…", "info");
    const cveFindings = [];
    for (const tech of this.technologies) {
      if (!tech.version) continue;
      const key = `${tech.name.toLowerCase()}/${tech.version.split(".").slice(0,2).join(".")}`;
      const cves = KNOWN_VERSION_CVES[key] || [];
      if (cves.length > 0) {
        this.log("CVE", `Version-matched ${cves.length} CVEs for ${tech.name} ${tech.version}`, "error");
        for (const cveId of cves) {
          const exploit = EXPLOIT_DB[cveId] || { available: false, complexity: "UNKNOWN" };
          const inKev = CISA_KEV_KNOWN.has(cveId);
          if (inKev) this.log("CVE", `⚠ ${cveId} is in CISA KEV — actively exploited!`, "error");
          cveFindings.push({
            type: "cve-finding", title: `${cveId} — ${tech.name} ${tech.version}`,
            severity: inKev ? "CRITICAL" : exploit.available ? "HIGH" : "MEDIUM",
            cvss: null, cveId, exploitAvailable: exploit.available, exploitType: exploit.type,
            exploitComplexity: exploit.complexity, inCisaKev: inKev,
            evidence: `Version-matched: ${tech.name} ${tech.version} is in affected range for ${cveId}`,
            service: tech.name, port: tech.port, confidence: "HIGH",
          });
        }
      } else {
        this.log("CVE", `No version-matched CVEs for ${tech.name} ${tech.version}`, "success");
      }
    }
    return cveFindings;
  }
}

// ValidatorAgent
export class ValidatorAgent {
  constructor(scanId, findings, reconData, log) {
    this.findings = findings;
    this.reconData = reconData;
    this.log = log;
  }
  async run() {
    this.log("VALIDATE", `Validating ${this.findings.length} raw findings…`, "info");
    return this.findings.map(f => {
      let fpRisk = "LOW";
      let note = "";
      if (["missing-hsts","missing-csp","missing-xframe","missing-xcontent","missing-referrer"].includes(f.type)) {
        note = "Header-only finding — not directly exploitable without chained vulnerabilities";
        if (f.severity === "CRITICAL" || f.severity === "HIGH") {
          this.log("VALIDATE", `Downgrading ${f.title} from ${f.severity} → correct severity`, "warn");
          f.severity = f.type === "missing-csp" ? "LOW" : "INFO";
          f.cvss = 3.0;
        }
      }
      if (f.type === "eol-os" || f.type === "eol-software") {
        fpRisk = "MEDIUM";
        note = "EOL increases risk but not auto-exploitable — requires specific CVE";
      }
      if (["mongodb-exposed","redis-exposed","elasticsearch-exposed"].includes(f.type)) {
        fpRisk = "MEDIUM";
        note = "Requires unauthenticated access verification — may have auth enabled";
      }
      return { ...f, falsePositiveRisk: fpRisk, validationNote: note };
    });
  }
}

// SeverityAgent
const SEVERITY_RULES = {
  "missing-hsts": { severity: "LOW", cvss: 3.5 },
  "missing-csp": { severity: "LOW", cvss: 4.3 },
  "missing-xframe": { severity: "LOW", cvss: 3.5 },
  "missing-xcontent": { severity: "INFO", cvss: 2.1 },
  "missing-referrer": { severity: "INFO", cvss: 1.8 },
  "missing-spf": { severity: "MEDIUM", cvss: 5.3 },
  "missing-dmarc": { severity: "MEDIUM", cvss: 5.3 },
  "server-header-disclosure": { severity: "INFO", cvss: 2.7 },
  "ftp-exposed": { severity: "MEDIUM", cvss: 5.3 },
  "rdp-exposed": { severity: "HIGH", cvss: 7.5 },
  "telnet-exposed": { severity: "HIGH", cvss: 8.0 },
  "mongodb-exposed": { severity: "CRITICAL", cvss: 9.8 },
  "redis-exposed": { severity: "CRITICAL", cvss: 9.8 },
  "elasticsearch-exposed": { severity: "CRITICAL", cvss: 9.1 },
  "smb-signing-disabled": { severity: "MEDIUM", cvss: 6.8 },
  "smbv1-enabled": { severity: "HIGH", cvss: 8.1 },
  "ftp-anonymous": { severity: "MEDIUM", cvss: 6.5 },
  "default-credentials": { severity: "CRITICAL", cvss: 9.8 },
  "sql-injection": { severity: "CRITICAL", cvss: 9.8 },
  "xss-stored": { severity: "HIGH", cvss: 7.4 },
  "xss-reflected": { severity: "MEDIUM", cvss: 6.1 },
  "rce": { severity: "CRITICAL", cvss: 9.8 },
  "lfi": { severity: "HIGH", cvss: 7.5 },
  "ssrf": { severity: "HIGH", cvss: 8.6 },
  "dns-zone-transfer": { severity: "HIGH", cvss: 7.5 },
};

export class SeverityAgent {
  constructor(scanId, findings, log) {
    this.findings = findings;
    this.log = log;
  }
  run() {
    return this.findings.map(f => {
      const rule = SEVERITY_RULES[f.type];
      if (rule && !f.type?.startsWith("cve-")) {
        if (rule.severity !== f.severity) {
          this.log("SEVERITY", `${f.title}: ${f.severity} → ${rule.severity} (CVSS ${rule.cvss})`, "warn");
        }
        return { ...f, severity: rule.severity, cvss: f.cvss || rule.cvss };
      }
      return f;
    });
  }
}

// ChainAgent
export class ChainAgent {
  constructor(scanId, findings, log) {
    this.findings = findings;
    this.log = log;
  }
  run() {
    const chains = [];
    const has = (type) => this.findings.some(f => f.type === type || f.type?.includes(type));

    if (has("smb-signing-disabled") && (has("weak-password") || has("default-credentials"))) {
      chains.push({ id: "CHAIN-001", title: "NTLM Relay → Domain Compromise", severity: "CRITICAL",
        steps: ["SMB signing disabled on domain systems","Position for NTLM relay attack (Responder/ntlmrelayx)","Relay captured credentials","Lateral movement to high-value targets","Domain privilege escalation"],
        likelihood: "HIGH", impact: "Full domain compromise", mitre: ["T1557.001","T1078","T1068","T1021.002"] });
      this.log("CHAIN", "⚠ CHAIN-001: NTLM Relay → Domain Compromise [CRITICAL]", "error");
    }
    if (has("rdp-exposed") && (has("eol-os") || has("weak-password"))) {
      chains.push({ id: "CHAIN-002", title: "RDP Brute Force → Ransomware Deployment", severity: "CRITICAL",
        steps: ["RDP exposed to internet","Credential brute force / stuffing","Initial foothold established","Lateral movement via SMB/RDP","Ransomware deployment"],
        likelihood: "HIGH", impact: "Full system compromise, ransomware risk", mitre: ["T1021.001","T1110","T1486","T1133"] });
      this.log("CHAIN", "⚠ CHAIN-002: RDP Brute Force → Ransomware [CRITICAL]", "error");
    }
    if (has("smbv1")) {
      chains.push({ id: "CHAIN-003", title: "SMBv1 → EternalBlue / WannaCry", severity: "CRITICAL",
        steps: ["SMBv1 protocol enabled","EternalBlue exploit (MS17-010)","SYSTEM-level code execution","Worm propagation / ransomware"],
        likelihood: "MEDIUM", impact: "Unauthenticated RCE — worm propagation", mitre: ["T1210","T1486","T1059"] });
      this.log("CHAIN", "⚠ CHAIN-003: SMBv1 EternalBlue Vector [CRITICAL]", "error");
    }
    if (has("sql-injection") && has("server-header-disclosure")) {
      chains.push({ id: "CHAIN-004", title: "Recon → SQL Injection → DB Exfiltration", severity: "CRITICAL",
        steps: ["Technology stack disclosed via server headers","SQL injection in web application","Database enumeration and credential dump","Potential xp_cmdshell OS command execution"],
        likelihood: "HIGH", impact: "Full DB compromise, potential RCE", mitre: ["T1190","T1005","T1059"] });
      this.log("CHAIN", "⚠ CHAIN-004: SQLi → DB Exfiltration [CRITICAL]", "error");
    }
    if (has("mongodb-exposed") || has("redis-exposed") || has("elasticsearch-exposed")) {
      chains.push({ id: "CHAIN-005", title: "Exposed Database → Data Exfiltration", severity: "CRITICAL",
        steps: ["Unauthenticated database service exposed","Direct data read without credentials","Full database exfiltration","Potential credential reuse attacks"],
        likelihood: "HIGH", impact: "Mass data exfiltration, compliance breach", mitre: ["T1530","T1005","T1078"] });
      this.log("CHAIN", "⚠ CHAIN-005: Exposed DB → Exfiltration [CRITICAL]", "error");
    }

    if (chains.length === 0) this.log("CHAIN", "No critical attack chains identified", "success");
    return chains;
  }
}

// MitreAgent
const FINDING_TO_ATTACK = {
  "sql-injection": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },{ id: "T1005", name: "Data from Local System", tactic: "Collection" }],
  "xss-stored": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "rce": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  "lfi": [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },{ id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" }],
  "ssrf": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },{ id: "T1018", name: "Remote System Discovery", tactic: "Discovery" }],
  "smb-signing-disabled": [{ id: "T1557.001", name: "LLMNR/NBT-NS Poisoning", tactic: "Credential Access" },{ id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" }],
  "smbv1-enabled": [{ id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },{ id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" }],
  "rdp-exposed": [{ id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement" },{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
  "default-credentials": [{ id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
  "ftp-exposed": [{ id: "T1005", name: "Data from Local System", tactic: "Collection" }],
  "missing-spf": [{ id: "T1566", name: "Phishing", tactic: "Initial Access" }],
  "missing-dmarc": [{ id: "T1566", name: "Phishing", tactic: "Initial Access" }],
  "mongodb-exposed": [{ id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" }],
  "redis-exposed": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  "server-header-disclosure": [{ id: "T1592", name: "Gather Victim Host Info", tactic: "Reconnaissance" }],
  "cve-finding": [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
};

export class MitreAgent {
  constructor(scanId, findings, log) {
    this.findings = findings;
    this.log = log;
  }
  run() {
    const matrix = {};
    this.findings.forEach(f => {
      const techs = FINDING_TO_ATTACK[f.type] || [];
      techs.forEach(t => {
        if (!matrix[t.tactic]) matrix[t.tactic] = [];
        if (!matrix[t.tactic].find(x => x.id === t.id))
          matrix[t.tactic].push({ ...t, finding: f.title });
      });
    });
    const tactics = Object.keys(matrix);
    this.log("MITRE", `Mapped to ${tactics.length} ATT&CK tactics: ${tactics.join(", ")}`, "info");
    return matrix;
  }
}
