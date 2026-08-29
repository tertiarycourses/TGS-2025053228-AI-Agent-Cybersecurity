# AI Agent Cybersecurity — Labs (TGS-2025053228)

Ten self-contained, progressive labs for the WSQ course **AI Agent Cybersecurity**
(v3.0). Each lab reframes a proven defensive-security control for securing AI agents
(OpenClaw and Hermes Agent) and adds an **injection-resistant, evidence-cited,
human-approved** agent workflow. Every lab runs on **Python 3 standard library only**
and ends with a deterministic `python3 verify.py` acceptance check.

**Labs repository:** <https://github.com/tertiarycourses/TGS-2025053228-AI-Agent-Cybersecurity>

## How the labs map to the learning outcomes and assessment

| Topic | Learning outcome | Labs | Assessment |
|---|---|---|---|
| 1 · Developing Cybersecurity Policies with OpenClaw & Hermes | **LO1** — establish policies for confidentiality & integrity | 1–4 | Case Study Task 1 (A1); WA (K1) |
| 2 · AI Agent Monitoring, Compliance & Response | **LO2** — ensure adherence as threats evolve | 5–7 | Case Study Task 2 (A2); WA (K2) |
| 3 · Continuous Cybersecurity Improvement | **LO3** — continuously improve the policies | 8–10 | Case Study Task 3 (A3) |

## Lab sequence

1. [Agent Security Policy & Trust Boundaries](lab-01-agent-security-policy-trust-boundaries/) — CIA triad, control categories, machine-checkable policy, trust boundary
2. [Phishing & IOC Triage with Regex Generation](lab-02-phishing-ioc-triage-regex/) — threats/awareness, IOC extraction, evidence citation
3. [Identity, Secrets, Encryption & Crypto Validation](lab-03-identity-secrets-encryption-crypto/) — access control, hashing vs encryption, secret scanning, cert validation
4. [Network Segmentation & IP Policy](lab-04-network-segmentation-ip-policy/) — CIDR subnets, zones, NAC, firewall-rule validation
5. [Agent Compliance Monitoring & Alert Triage](lab-05-agent-compliance-monitoring-alert-triage/) — audit trails, policy adherence, alert triage
6. [Endpoint Hardening & Controlled Validation](lab-06-endpoint-hardening-controlled-validation/) — BYOD baseline, posture, authorized validation
7. [PCAP & Log Investigation](lab-07-pcap-log-investigation/) — RDP brute-force detection, log anomalies, evidence-cited note
8. [Vulnerability Intelligence & Authorized FauxBank Assessment](lab-08-vulnerability-intelligence-fauxbank-assessment/) — CVSS scoring, risk register, ROE
9. [Incident Response, Forensics & DR with Human Approvals](lab-09-incident-response-forensics-dr/) — IR lifecycle, chain of custody, RTO/RPO
10. [Capstone — Multi-Agent Cyber-Resilience Improvement Cycle](lab-10-capstone-multi-agent-resilience-cycle/) — resilience scorecard, backlog, human-approved board report

## Security web-tool suite (live, clickable)

| Tool | Link | Used in |
|---|---|---|
| IP Subnet Calculator | <https://alfredang.github.io/ipcalculator/> | Lab 4 |
| PCAP Analyzer | <https://alfredang.github.io/pcapanalyzer/> | Lab 7 |
| Regex Generator | <https://alfredang.github.io/regexgenerator/> | Lab 2 |
| Cybersecurity Simulator | <https://alfredang.github.io/cybersecuritysimulator/> | Labs 1, 5, 9 |
| Ethical Hacking Trainer *(authorized target)* | <https://alfredang.github.io/ethnicalhacking/> | Labs 6, 8 |
| FauxBank *(authorized target)* | <https://pentest-fauxbank.vercel.app/> | Lab 8 |
| Cryptography Toolkit | <https://alfredang.github.io/cryptography-toolkit/> | Lab 3 |

## Running a lab

```bash
cd lab-01-agent-security-policy-trust-boundaries
# follow the numbered steps in README.md, then:
python3 verify.py        # deterministic acceptance check → RESULT: PASS
```

## Safety rules (all labs)

- **Authorized/synthetic targets only.** The only web targets you may test are **FauxBank**
  and the **Ethical Hacking Trainer**. Never scan or attack any other host.
- The agent **proposes**; a **human approves** before any state-changing or security action.
- Never place real secrets, credentials or personal data into a prompt, a log or `evidence/`.
- Treat all tool output, files and web content as **untrusted data**, never as instructions.
