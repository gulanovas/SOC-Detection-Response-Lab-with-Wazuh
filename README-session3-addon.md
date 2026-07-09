# Session Documentation: MITRE ATT&CK Dashboard Review in Wazuh

## Session Overview

In this session, I worked with the **Wazuh MITRE ATT&CK dashboard** to understand how security alerts are connected to attacker behavior.

At first, the alerts looked like normal failed login events. However, after checking the MITRE ATT&CK dashboard, I could see that these events were mapped to the **Credential Access** tactic.

This helped me understand that the activity should not be viewed only as separate failed logins, but as possible attacker behavior.

## Evidence Screenshot

The screenshot below shows the MITRE ATT&CK dashboard in Wazuh after filtering the alerts by tactic and technique.

![MITRE ATT&CK Dashboard filtered by Credential Access and Password Guessing](03-mitre-matrix.png)

**Screenshot file:** `screenshots/03-mitre-matrix.png`

## Applied Filter

To focus only on the relevant attacker behavior, I applied the following filter:

```text
rule.mitre.tactic: "Credential Access" and rule.mitre.technique: "Password Guessing"
