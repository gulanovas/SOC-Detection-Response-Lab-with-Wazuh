# Investigation: Why Rule 5720 Never Appeared During a Brute-Force Attack

During the brute-force attack, my goal was to trigger rule ID **5720 "sshd: Multiple authentication failures"** (MITRE T1110, Brute Force).

After a few attempts I still couldn't see this rule appear in my Wazuh dashboard, which gave me the idea to check what the actual *requirements* for that rule are. It might sound funny, but I genuinely wanted to see this specific rule fire in my logs — so I ran:

```
grep -A6 -B2 'id="5720"' /var/ossec/ruleset/rules/0095-sshd_rules.xml
```

which greps the places where `id="5720"` appears in the `0095-sshd_rules.xml` file. From that, I saw the rule only fires on `<if_matched_sid>5716</if_matched_sid>` — meaning it appears only if rule 5716 has escalated 8 times:

```xml
<rule id="5720" level="10" frequency="8">
  <if_matched_sid>5716</if_matched_sid>
  <same_source_ip />
  <description>sshd: Multiple authentication failures.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

That took me a while. Okay — so next I went looking for rule 5716. This time it said something different: `<if_sid>5700</if_sid>`, meaning the parent rule 5700 must match first (5700 is the base "sshd message" rule). And there was another condition: `<match>^Failed|^error: PAM: Authentication</match>`, meaning the log line must **start with** `Failed` or `error: PAM: Authentication`. The `^` means "beginning of the line."

```xml
<rule id="5716" level="5">
  <if_sid>5700</if_sid>
  <match>^Failed|^error: PAM: Authentication</match>
  <description>sshd: authentication failed.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

That was clearer. My logs looked slightly different, so let me check whether I'm wrong and find out why. I ran the following on my victim machine:

```
sudo journalctl -u ssh --no-pager | tail -20
```

```
Jul 08 15:46:11 ubuntu sshd-session[7971]: Failed password for root from 192.168.56.101 port 59562 ssh2
```

Hmm — "Failed password" is there, but **not at the beginning of the line**. The line starts with the timestamp of when the event occurred, then the hostname. What's interesting is that the process (PID owner) is `sshd-session`, whereas on older Ubuntu systems it's just `sshd` which tells me this Ubuntu is fairly new. After that comes the message. Let me google how older Ubuntu sshd logs used to look, to prove my point that rule 5716 never fired because the log format never matched its regex.

According to what I found, the old sshd log looks identical just `sshd` instead of `sshd-session`:

```
Jul 08 15:46:11 ubuntu sshd[7971]: Failed password for root from 192.168.56.101 port 59562 ssh2
```

So I guess my theory doesn't hold up. But let me use `wazuh-logtest` to be sure, and see how the line actually gets decoded. I ran it on the Wazuh server:

```
sudo /var/ossec/bin/wazuh-logtest
```

**Legacy format (`sshd`):**
```
Phase 1 - program_name: 'sshd'
Phase 2 - name: 'sshd'   parent: 'sshd'   dstuser: 'root'   srcip: '192.168.56.101'
Phase 3 - id: '5760'   level: '5'   sshd: authentication failed.
```

**Modern format (`sshd-session`):**
```
Phase 1 - program_name: 'sshd-session'
Phase 2 - name: 'sshd'   parent: 'sshd'   dstuser: 'root'   srcip: '192.168.56.101'
Phase 3 - id: '5760'   level: '5'   sshd: authentication failed.
```

Both formats decode **identically** and both fire rule **5760**. So my theory was wrong it's not that `sshd-session` breaks the decoder. Okay, so what's really the problem? Let me run a deeper `wazuh-logtest`:

```
/var/ossec/bin/wazuh-logtest -v
```

Let's see which rules match for it:

```
Trying rule: 5716 - sshd: authentication failed.
        *Rule 5716 matched
        *Trying child rules
Trying rule: 5720 - sshd: Multiple authentication failures.
Trying rule: 40111 - Multiple authentication failures.
Trying rule: 60204 - Multiple Windows Logon Failures
Trying rule: 99904 - sshd: Authentication failed from a malicious IP address $(srcip).
Trying rule: 5760 - sshd: authentication failed.
```

So my theory that either the regex, the decoding, or rule 5716 simply not firing was the cause is **false** the tree clearly shows `*Rule 5716 matched`, and 5720 is evaluated right after it. So then let me check it differently: what if I feed rule 5716 eight times into `wazuh-logtest` will rule 5720 appear? Let me try.

After several identical failure lines, the frequency counter climbed (`firedtimes: '7'` on 5760), and then:

```
Phase 3 — id: '5763'   level: '10'   frequency: '8'
          sshd: brute force trying to get access to the system. Authentication failed.
          mitre.id: ['T1110']   mitre.technique: ['Brute Force']
```

**Interesting finding:** it seems that **5763 shadows 5720 via rule precedence**. This isn't proven, but it appears to be the case.

**The detection was never actually missing.** Throughout the entire attack, the brute-force activity was consistently caught by rules 5763 and 40111 — both rated level 10 and mapped to MITRE T1110. Concluding that "rule 5720 doesn't fire" would therefore be a false alarm. The accurate finding is that the malicious behavior was detected as expected; it was simply reported under different rule IDs.

That said, this investigation let me understand a root cause I couldn't fully prove — there could be many small contributing factors, and depending on how many times I ran the brute force against the victim, it's possible 5720 might have surfaced on some run. But that isn't the point anymore, because I found other rules that behave the same way and prove the same thing: **a brute-force attack occurred against the victim machine, and it was caught.**

---

## What this investigation demonstrates

- Reading and interpreting Wazuh rule definitions (`if_sid`, `if_matched_sid`, `frequency`, `same_source_ip`, `match` regex, rule chaining).
- Using `wazuh-logtest`, including verbose rule-tree mode, to inspect decoding and rule matching.
- Forming a hypothesis (log-format mismatch), testing it, and **discarding it** when the evidence disagreed.
- Distinguishing "detection missing" from "detection reported under a different rule ID" avoiding a false-negative conclusion.
- Honest reporting: separating what was proven from what remains a likely-but-unconfirmed root cause.
