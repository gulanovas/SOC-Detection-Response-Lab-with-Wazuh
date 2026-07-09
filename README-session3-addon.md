## Session 3: Mapping Detections to MITRE ATT&CK

In this session my goal was to see the brute force from Session 1 mapped onto the MITRE ATT&CK framework. Wazuh already tags every alert with its ATT&CK technique, so instead of reading the attack as a pile of failed logins I wanted to see it framed as a specific adversary behavior.

I opened the MITRE ATT&CK module in the Wazuh dashboard and set the time range to cover my attack. The brute-force activity showed up under:

- **Tactic:** Credential Access
- **Technique:** T1110 (Brute Force)

When I clicked on the technique it showed me all the alerts feeding into it. All my Session 1 detections (5760, 5710, 5763, 40111 and the PAM/syslog rules) rolled up under this single technique, because they are all the same thing underneath: someone trying to get valid credentials by guessing them.

What I found useful here is that the framework gives the attack a name and a place in the bigger picture. It is not just "a lot of failed logins on victim-ubuntu from 192.168.56.101". It is the Credential Access phase, which usually comes right before things like persistence or privilege escalation, which is exactly what I did in Session 2 when I created the backdoor account. So the two sessions connect: first the attacker tries to get in (T1110), then once in they try to stay in (T1136).

A few reasons this mapping is worth doing:

- It gives every detection a standard label that means the same thing everywhere, so T1110 is understood by any tool, report or analyst.
- It puts a single alert into the context of an attack lifecycle, so I can think about what the attacker would likely try next.
- It shows which techniques my setup can currently detect and where the gaps are.

![MITRE ATT&CK dashboard filtered by Credential Access and Brute Force (T1110), showing the Session 1 detections mapped to the technique](screenshots/03-mitre-matrix.png)

*Wazuh MITRE ATT&CK module showing the brute-force detections mapped to T1110 (Credential Access).*

**Tactic:** Credential Access · **Technique:** T1110 (Brute Force)
