## Session 2: File Integrity Monitoring and Detecting Persistence

After the successful brute force, the victim machine (`192.168.56.103`) is under the attacker's control and the root password is known. This session simulates what an attacker does *next* (establishing persistence) and demonstrates how Wazuh's File Integrity Monitoring (FIM) catches it, mapped to **MITRE T1136 (Create Account)**.

### Setup: real-time FIM

FIM (Wazuh's `syscheck` module) was configured on the victim to watch `/etc` in real time, capturing content changes as they happen:

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
```

- `realtime="yes"`: alert the instant a file changes
- `check_all="yes"`: track size, permissions, ownership, and content hashes
- `report_changes="yes"`: capture *what* changed inside the file

### The attacker's move: planting a backdoor account

> *Attacker's reasoning:* "We control the box and know the root password. But what if they detect us and change it, or block our IP and cut our connection? Let's quickly create a second user as a fallback, call it `backdoor`."

```
sudo useradd -m -s /bin/bash backdoor
```
Creates the account with its own home directory (`-m`) and a usable login shell (`-s /bin/bash`).

```
sudo usermod -aG sudo backdoor
```
Adds the account to the `sudo` group for admin rights. `-aG` **appends** the group while keeping existing ones, which is critical because `-G` alone would overwrite them.

> *Attacker's reasoning:* "Now we log out of root. Hopefully they'll focus on securing the root account and never notice the new user sitting quietly in the background."

### The analyst's view: the persistence is caught immediately

Within seconds, new alerts appeared in Wazuh. Not only was the root login visible; the attacker's "quiet" backdoor account lit up across **three FIM rules**:

| Rule | What it revealed |
|------|------------------|
| **5902** | A new user was added to the system |
| **554** | New file(s) added (the account's files / home directory) |
| **550** | Integrity checksum changed on files in `/etc`, showing the account was given a default shell and added to the `sudo` group |

So from the defender's side, the full picture was reconstructed from the alerts alone: *an attacker logged in as root, created a new user, gave that user a login shell, and escalated it into the sudo group.* The one thing not yet seen was any login **from** the new account, so persistence had been planted but not yet used.

### Response: the defender's options

Once the intrusion is detected, the analyst has to decide how to respond. First, the rogue account was removed:
```
sudo userdel -r backdoor
```
(`-r` also deletes the home directory.)

> *Defender's reasoning:* "Should we block the attacker's IP at the firewall to cut them off completely?"
> ```
> sudo ufw deny from 192.168.56.101 to any port 22
> ```
> "…rotating the compromised credentials handles it for now, but firewalling the source (`192.168.56.101`, the attacker's host) is the stronger containment step if the activity continues."

This is the containment decision a SOC analyst faces after confirming an intrusion: remove the persistence, rotate the compromised credentials, and, if the activity persists, block the attacking source IP (`192.168.56.101`) at the firewall to sever access entirely. Each of these response actions is a deliberate defensive step, not part of the attack.

### Why blocking one IP is not enough: defense in depth

Blocking the attacker's IP is a reasonable first move, but on its own it is a shallow, temporary fix. A determined attacker is not tied to a single address and has many ways to come back from a different source:

- **Change source IP.** Reconnect from a new address via a VPN, a cloud VM, or a rented server. A home attacker can often just reset their router for a fresh ISP-assigned IP.
- **Proxies and Tor.** Route the attack through proxy chains or the Tor network, presenting a constantly rotating exit IP that a single firewall rule can never keep up with.
- **Pivoting.** If they still hold any foothold (an unremoved backdoor account, a cron job, an SSH key they planted), they can re-enter from an already-trusted internal host, bypassing the IP block entirely.
- **Spoofing or compromised hosts.** Launch from other compromised machines, making the traffic appear to originate from legitimate or varied sources.

Because a single blocked IP is trivially bypassed, the response should be layered (defense in depth) rather than a one-off rule:

1. **Harden the service.** Disable direct root SSH login (`PermitRootLogin no`), enforce key-based authentication, and restrict SSH to known management networks.
2. **Rate-limit and auto-block.** Deploy `fail2ban` or Wazuh active response to automatically ban any source that trips the brute-force detection, instead of blocking IPs by hand after the fact.
3. **Firewall by policy, not by single address.** Default-deny inbound, and allow SSH only from a trusted allow-list, rather than reacting with one `deny` rule per attacker.
4. **Add an IPS/IDS layer.** An Intrusion Prevention System (for example Suricata inline, or an OPNsense/pfSense IPS) can recognise and block brute-force and exploitation patterns in real time at the network edge, stopping this class of attack before it ever reaches the host, regardless of which IP it comes from.
5. **Verify eradication.** Confirm no persistence remains (rogue accounts, authorized_keys, cron or systemd jobs) so the attacker cannot simply pivot back in from a new address.

In short: blocking the IP treats the symptom, while layered controls and an IPS treat the cause. The goal is not just to remove this attacker, but to make the same attack fail the next time it arrives from anywhere.

### Key takeaway

The attacker assumed a newly created user would go unnoticed if attention stayed on the root account. In reality, account creation is one of the loudest things you can do on a monitored host. It modifies `/etc/passwd`, `/etc/shadow`, and `/etc/group`, all of which FIM watches, and it generates an independent "new user added" log event. The persistence attempt was fully detected and attributed before the backdoor was ever used.

*Evidence:* `screenshots/02-fim-change.png`

**Detections:** rules 550, 554, 5902 · MITRE ATT&CK T1136 (Create Account)
