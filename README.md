# SOC Detection & Response Lab with Wazuh

A hands-on home lab where I stand up a monitored environment, launch real attacks against it, and detect and investigate them the way a SOC analyst would. The focus is on **detection engineering and investigation** — not just running a tool, but understanding *why* each alert fires, tracing detections through the rule chain, and verifying findings with the platform's own tooling.

**Stack:** Wazuh 4.14.6 (SIEM) · Kali Linux (attacker) · Ubuntu Server (victim) · VirtualBox · MITRE ATT&CK

---

## Architecture

Three virtual machines on an isolated host-only lab network:

| Role | Host | Address | Purpose |
|------|------|---------|---------|
| **Attacker** | Kali Linux | `192.168.56.101` | Launches attacks (Hydra) |
| **Victim** | Ubuntu Server | `192.168.56.103` | Monitored endpoint running the Wazuh agent |
| **SIEM** | Wazuh Server | `192.168.56.102` | Collects, correlates, and alerts |

Attack traffic flows **attacker → victim**, and the victim's agent ships telemetry to the **Wazuh manager**, which decodes it, matches it against the ruleset, and raises alerts mapped to MITRE ATT&CK.

---

## What this lab demonstrates

- Deploying and configuring a full Wazuh SIEM with an enrolled endpoint agent
- Generating realistic attack telemetry and detecting it end-to-end
- Alert triage and investigation: pivoting on source IP, reconstructing the attack timeline
- Reading and interpreting Wazuh rules (`if_sid`, `if_matched_sid`, `frequency`, `same_source_ip`, rule chaining and precedence)
- Root-cause analysis of detection behavior using `wazuh-logtest`
- Mapping detections to MITRE ATT&CK

---

## Completed work

### 1. Environment build & agent enrollment

Deployed a three-VM lab from scratch: imported the Wazuh OVA, built a minimal Ubuntu victim, configured an isolated host-only network so all hosts could communicate, and enrolled the Ubuntu agent with the manager. Worked through real deployment issues along the way — host-only DHCP addressing, agent-to-manager enrollment over the correct interface, and confirming the agent reported **Active** in the dashboard.

*Evidence:* `screenshots/00-agent-active.png`

---

### 2. SSH brute-force attack — multi-tier detection

Launched a controlled SSH brute-force attack from Kali against the Ubuntu victim using Hydra, then detected and attributed it in Wazuh. The attack was caught across **multiple rules and multiple log pipelines simultaneously**, which is exactly the kind of corroboration a SOC analyst relies on to confirm an alert is real rather than a decoder artifact.

**Detections observed** — all attributed to source IP `192.168.56.101` against agent `victim-ubuntu`, all mapped to **MITRE T1110 (Brute Force):**

| Source | Rule | Meaning |
|--------|------|---------|
| sshd decoder | 5760 | Per-attempt authentication failure (valid user) |
| sshd decoder | 5710 | Login attempt for a non-existent user (enumeration) |
| PAM / syslog | 5503, 2502 | Independent auth-failure corroboration |
| sshd (aggregated) | **5763** — level 10 | Brute force: many failures from one source |
| attack patterns | **40111** — level 10 | Multiple authentication failures, same source IP |

The single attack triggered detection at three tiers — individual failures, an sshd-specific brute-force alert, and a cross-source attack-pattern alert — demonstrating how low-level events roll up into high-severity, source-attributed detections.

*Evidence:* `screenshots/01-bruteforce.png` (alert histogram + rule breakdown with source IP visible)

**Realistic tuning note:** running Hydra too aggressively (`-t 8`) tripped the victim's SSH connection rate-limiting (`MaxStartups`), causing the tool to abort. Slowing the attack (`-t 4 -W 1`) let each attempt complete, which produced *more* complete telemetry — surfacing PAM/syslog rules (2502) that the faster attack skipped. A useful reminder that attack speed changes what gets logged, and therefore what gets detected.

---

### 3. Root-cause investigation: a non-firing correlation rule

While testing, I set out to trigger rule **5720 ("Multiple authentication failures")** and found it never appeared in the dashboard — despite thousands of failed logins that should have satisfied it. Rather than report the detection as simply broken, I ran a full root-cause investigation.

Using `wazuh-logtest` (including verbose rule-tree mode) and direct inspection of the rule definitions, I formed and **discarded** several hypotheses based on evidence:

- **Log-format mismatch** (modern `sshd-session` vs legacy `sshd`) — disproved: both decode identically.
- **Rule 5716 never firing** — disproved: the rule tree shows it does fire.

The evidence pointed to **rule precedence** — rule 5763 occupies the same detection niche (8 SSH failures, same threshold) deeper in the rule chain and consistently wins the reported alert, shadowing 5720 in the output.

**Key operational finding:** the detection was never actually missing. The brute force was caught the entire time by rules 5763 and 40111 — both level 10, both MITRE T1110. Concluding "5720 doesn't fire" would have been a false alarm; the behavior was detected as expected, simply reported under different rule IDs.

Full writeup with commands, `wazuh-logtest` output, and reasoning: **[`wazuh-5720-investigation.md`](./wazuh-5720-investigation.md)**

This investigation is the strongest single artifact in the lab — it mirrors a real SOC task ("a detection isn't firing, find out why"), practices hypothesis-driven troubleshooting, and demonstrates the discipline of separating what's *proven* from what remains a likely-but-unconfirmed root cause.

---

## Repository contents

```
screenshots/    Alert evidence (agent active, brute-force detections)
wazuh-5720-investigation.md   Full root-cause investigation writeup
configs/        Relevant agent / manager configuration
README.md       This file
```

---

## Skills evidenced

`SIEM operation` · `Endpoint agent deployment` · `Alert triage & investigation` · `Log analysis` · `Detection rule interpretation` · `Root-cause analysis` · `MITRE ATT&CK mapping` · `Hypothesis-driven troubleshooting`
