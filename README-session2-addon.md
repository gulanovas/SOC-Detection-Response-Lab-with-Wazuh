## Session 2 — File Integrity Monitoring: Detecting Persistence

After the successful brute force, the victim machine (`192.168.56.103`) is under the attacker's control and the root password is known. This session simulates what an attacker does *next* — establishing persistence — and demonstrates how Wazuh's File Integrity Monitoring (FIM) catches it, mapped to **MITRE T1136 (Create Account)**.

### Setup — real-time FIM

FIM (Wazuh's `syscheck` module) was configured on the victim to watch `/etc` in real time, capturing content changes as they happen:

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
```

- `realtime="yes"` — alert the instant a file changes
- `check_all="yes"` — track size, permissions, ownership, and content hashes
- `report_changes="yes"` — capture *what* changed inside the file

### The attacker's move — planting a backdoor account

> *Attacker's reasoning:* "We control the box and know the root password. But what if they detect us and change it, or block our IP and cut our connection? Let's quickly create a second user as a fallback — call it `backdoor`."

```
sudo useradd -m -s /bin/bash backdoor
```
Creates the account with its own home directory (`-m`) and a usable login shell (`-s /bin/bash`).

```
sudo usermod -aG sudo backdoor
```
Adds the account to the `sudo` group for admin rights. `-aG` **appends** the group while keeping existing ones — critical, because `-G` alone would overwrite them.

> *Attacker's reasoning:* "Now we log out of root. Hopefully they'll focus on securing the root account and never notice the new user sitting quietly in the background."

### The analyst's view — the persistence is caught immediately

Within seconds, new alerts appeared in Wazuh. Not only was the root login visible — the attacker's "quiet" backdoor account lit up across **three FIM rules**:

| Rule | What it revealed |
|------|------------------|
| **5902** | A new user was added to the system |
| **554** | New file(s) added (the account's files / home directory) |
| **550** | Integrity checksum changed on files in `/etc` — showing the account was given a default shell and added to the `sudo` group |

So from the defender's side, the full picture was reconstructed from the alerts alone: *an attacker logged in as root, created a new user, gave that user a login shell, and escalated it into the sudo group.* The one thing not yet seen was any login **from** the new account — persistence had been planted but not yet used.

### Response

The rogue account was removed:
```
sudo userdel -r backdoor
```
(`-r` also deletes the home directory.)

> *Attacker's afterthought:* "Should we firewall them out to keep control?"
> ```
> sudo ufw deny from 203.0.113.50 to any port 22
> ```
> "…no, we'll just change the password, that's fine for now."

This captures the attacker's decision-making — and from the blue-team side, each of those actions (a new firewall rule, a password change) would *also* generate detectable events, reinforcing that every move to maintain control leaves a trace.

### Key takeaway

The attacker assumed a newly created user would go unnoticed if attention stayed on the root account. In reality, **account creation is one of the loudest things you can do on a monitored host** — it modifies `/etc/passwd`, `/etc/shadow`, and `/etc/group`, all of which FIM watches, and it generates an independent "new user added" log event. The persistence attempt was fully detected and attributed before the backdoor was ever used.

*Evidence:* `screenshots/02-fim-persistence.png`

**Detections:** rules 550, 554, 5902 · MITRE ATT&CK T1136 (Create Account)
