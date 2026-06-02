# PHANTM — AI VAPT Framework v2.0

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝
```

**AI-Powered Penetration Testing & Vulnerability Assessment Platform**  
Powered by Llama 3.3 70B via Groq (100% free)

---

## Quick Start

### Step 1 — Get a free Groq API key

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up (free, no credit card)
3. API Keys → Create Key → copy it (`gsk_...`)

### Step 2 — Install and run

**Open TWO terminal windows:**

**Terminal 1 — Backend:**
```bash
cd backend
npm install
npm run dev
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Open browser:** http://localhost:5173

Paste your Groq API key when prompted.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PHANTM PIPELINE                      │
├──────────┬──────────┬──────────┬──────────┬────────────┤
│  RECON   │ FINGERPT │   CVE    │ VALIDATE │  SEVERITY  │
│ crt.sh   │ Version  │ NVD/KEV  │ FP Reduc │ CVSS v3.1  │
│ HackerTgt│ Extract  │ Matching │ Precondit│ Calibrated │
└────┬─────┴────┬─────┴────┬─────┴────┬─────┴─────┬──────┘
     │          │          │          │           │
┌────▼──────────▼──────────▼──────────▼───────────▼──────┐
│              ATTACK CHAIN CORRELATION                    │
│   SMB Signing + Weak Pass = NTLM Relay → Domain Comp   │
│   RDP Exposed + EOL OS    = Ransomware Path            │
│   Exposed DB              = Data Exfiltration Chain    │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│              MITRE ATT&CK MAPPING                       │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│         LLM REASONING — Llama 3.3 70B (Groq)           │
│  Evidence-based only. No hallucination. No invented CVEs│
└─────────────────────────────────────────────────────────┘
```

## Features

| Feature | Status |
|---------|--------|
| 8-stage deterministic pipeline | ✅ |
| Real-time WebSocket scan logs | ✅ |
| CVE version matching (NVD) | ✅ |
| CISA KEV flagging | ✅ |
| Attack chain correlation | ✅ |
| MITRE ATT&CK mapping | ✅ |
| Visual attack graph (D3 canvas) | ✅ |
| Vulnerability hunter (multi-target) | ✅ |
| AI chat analyst | ✅ |
| Executive / Technical / Compliance reports | ✅ |
| SQLite persistence (no setup needed) | ✅ |
| Severity calibration (no inflated scores) | ✅ |
| False positive reduction | ✅ |

## Pages

| Page | Description |
|------|-------------|
| Dashboard | Scan history, stats, backend status |
| Scan Engine | 8-stage pipeline with live WebSocket logs |
| Vuln Hunter | Scan multiple targets for specific vulnerability |
| AI Analyst | Chat with Llama 3.3 about findings |
| Attack Graph | Visual D3 node graph of attack paths |
| MITRE ATT&CK | Matrix and list views of covered techniques |
| Reports | Executive, Technical, Compliance report generation |

## Severity Philosophy

Unlike generic scanners, PHANTM calibrates severity accurately:

| Finding | Generic Scanner | PHANTM |
|---------|----------------|--------|
| Missing HSTS | CRITICAL | LOW |
| Missing CSP | HIGH | LOW |
| SMB signing disabled (no domain) | CRITICAL | MEDIUM |
| EOL software (no exploit) | CRITICAL | HIGH |
| RDP + EOL + weak password | — | CRITICAL (chain) |

## Free APIs Used

- **crt.sh** — Certificate transparency subdomain enum
- **HackerTarget** — DNS lookup, port scan, HTTP headers
- **NVD API v2** — CVE lookups and CVSS scores
- **CISA KEV** — Known exploited vulnerabilities feed
- **Groq** — Llama 3.3 70B inference (free tier)

## Legal Notice

**For authorized security testing only.**  
Never scan targets you don't own or have explicit written permission to test.  
Unauthorized scanning is illegal in most jurisdictions.
