## Session 3: Mapping Detections to MITRE ATT&CK

The goal of this session was to stop viewing the attack as a raw pile of failed logins and start viewing it the way a SOC analyst does: as an adversary operating in a specific phase of an intrusion. Wazuh performs this mapping automatically, tagging each detection with its MITRE ATT&CK technique and tactic.

### What the module shows

Opening the Wazuh **MITRE ATT&CK** module and filtering to the attack window, the brute-force activity from Session 1 appears mapped onto the framework under:

- **Tactic:** Credential Access
- **Technique:** T1110 (Brute Force)

Clicking the technique reveals every alert feeding it. All of the Session 1 detections (rules 5760, 5710, 5763, 40111, and the corroborating PAM/syslog rules) roll up under this single technique, because they are all evidence of the same adversary behavior: attempting to obtain valid credentials by guessing them.

### The reframe: from events to attacker behavior

This is the core lesson of the session. The same data can be read two completely different ways:

- **Log-watcher view:** "There are roughly 1,467 authentication-failure events on this host."
- **Analyst view:** "An adversary is in the Credential Access phase, attempting T1110 (Brute Force) against `victim-ubuntu` (192.168.56.103) from `192.168.56.101`."

The second framing is what matters operationally. It describes *what the attacker is trying to achieve* and *where they are in their operation*, rather than just counting noise. An analyst reports "we have credential-access activity against a host," not "there are a lot of failed logins." That shift, from events to intent, is the difference between watching logs and doing analysis.

### Why ATT&CK mapping matters

- It gives every detection a shared, standard vocabulary that analysts, tools, and reports all understand (T1110 means the same thing everywhere).
- It places an isolated alert into the context of an attack lifecycle, so you can reason about what the adversary is likely to do next (Credential Access typically precedes Lateral Movement, Persistence, or Privilege Escalation, which is exactly what Session 2's backdoor account represented).
- It lets a defender measure coverage: which tactics and techniques the environment can currently detect, and where the blind spots are.

### Key takeaway

Mapping detections to MITRE ATT&CK turns a stream of low-level events into a description of adversary behavior within a recognised attack framework. The Session 1 brute force is not just "failed logins"; it is the Credential Access phase of a potential intrusion, and framing it that way is what allows an analyst to prioritise, communicate, and anticipate the attacker's next move.

![MITRE ATT&CK dashboard filtered by Credential Access and Brute Force (T1110), showing the Session 1 detections mapped to the technique](screenshots/03-mitre-matrix.png)

*Wazuh MITRE ATT&CK module showing the brute-force detections mapped to T1110 (Credential Access).*

**Tactic:** Credential Access · **Technique:** T1110 (Brute Force)
