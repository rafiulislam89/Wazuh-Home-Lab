# Active Response - Automated Attacker IP Blocking

Wazuh detects the brute-force attack, then automatically blocks the attacker's IP on the Windows endpoint and removes the block after 300 seconds.

This scenario continues [Brute Force (SMB)](../Wazuh_Brute_Force_SMB/README.md), which ended with the attack succeeding and no response taken.

---

## Goal

Move from detection to response. Rule `100100` fires → the attacker IP is blocked at the endpoint firewall → the block expires automatically.

---

## Environment

| Host | IP | Role |
|---|---|---|
| Ubuntu Server | 192.168.56.101 | Wazuh manager, indexer, dashboard |
| Windows 11 | 192.168.56.102 | Endpoint, Wazuh agent |
| Kali Linux | 192.168.56.103 | Attacker |

---

## Configuration

Wazuh server, `/var/ossec/etc/ossec.conf`:

![Active Response configuration](screenshots/01-ossec-config.png)

`location: local` runs the response on the endpoint that generated the alert. `timeout: 300` removes the block after five minutes.

---

## Problem 1 - the built-in script blocked nothing

The first attempt used Wazuh's built-in `netsh.exe`. Rule `657` fired, confirming the response executed, but the attacker was never blocked - a second attack inside the timeout window succeeded completely.

The agent log gave the reason:

```
active-response/bin/netsh.exe: Cannot read 'srcip' from data
```

Windows event 4625 does not populate the `srcip` field Wazuh's script expects. The attacker IP is present in the alert, under `data.win.eventdata.ipAddress`.

**This is the core finding of the scenario.** The response ran, reported success, and did nothing - a failure mode that is invisible unless you verify the block itself rather than trusting the alert.

---

## Solution - custom Active Response script

[`custom-netsh-block.py`](custom-netsh-block.py), compiled with PyInstaller and deployed to the agent's `active-response/bin/` directory. It reads the IP from the correct field and applies a Windows Firewall rule via `netsh`.

![extract_ip function](screenshots/03-extract-ip-function.png)

The function tries `parameters.keys` first, then falls back to the alert, because the `add` and `delete` invocations do not carry the IP in the same place.

---

## Problem 2 - the unblock never ran

The block worked. The unblock started and hung:

```
17:14:44 custom-netsh-block.exe: Started
17:14:44 custom-netsh-block.exe: BLOCKED 192.168.56.103
17:14:44 custom-netsh-block.exe: Ended
17:19:44 custom-netsh-block.exe: Started
              (nothing further)
```

Two separate causes, found in sequence:

**Deadlock on stdin.** The script used `readline()`, which returns only on a newline or a closed pipe. `wazuh-execd` does not reliably terminate the delete message with a newline, so the read never returned. Replaced with a reader that consumes stdin until the buffer parses as valid JSON.

**Missing keys.** With the deadlock fixed, the script reported `No keys in delete message` - the delete invocation re-sends the original alert rather than a keys list. Fixed by the fallback in `extract_ip()`.

---

## Problem 3 - the response worked but produced no alert

With block and unblock both functioning, nothing appeared in the dashboard. Rule `657` had fired for the built-in `netsh.exe` but not for the custom script.

Cause: Wazuh's Active Response decoder parses the **full incoming JSON message** written to `active-responses.log`. The custom script logged only its own `check_keys` message, which the decoder ignores. Adding one line - writing the received message to the log - restored `657`.

A control that works but generates no telemetry is indistinguishable from one that is not running.

---

## Custom rules

`657` is generic: it fires for every Active Response on the system, for both `add` and `delete`, at level 3. It cannot distinguish which script ran or what it did.

Two rules were added to separate the block and the expiry:

![Custom rules](screenshots/02-local-rules.png)

Both are level 3. A successful automated response is informational, not an incident - raising the level would train an analyst to ignore it.

---

## Result

![Full detection and response chain](screenshots/04-alerts-full-chain.png)

| Time | Rule | Event |
|---|---|---|
| 17:14:29 – 17:14:41 | 60122 | Failed logon attempts |
| 17:14:43 | 100100 | Brute-force detected |
| 17:14:44 | 100201 | Attacker IP blocked |
| 17:19:46 | 100202 | Block expired, IP unblocked |

Endpoint log at block:

![Agent log — block applied](screenshots/05-ar-log-block.png)

Endpoint log at expiry:

![Agent log — block removed](screenshots/06-ar-log-unblock.png)

`netsh rc=0` on both confirms the firewall rule was created and then deleted on the endpoint - not merely that the script ran.

---

## Side finding - the endpoint silently changed its own attack surface

Mid-testing, SMB stopped responding. Windows had classified the Host-Only adapter as a **Public** network, which disables the File and Printer Sharing inbound rules. The endpoint had removed its own exposed service without any action from the lab.

Setting both interfaces to Private restored it.

The detection had not broken. It simply stopped receiving traffic - the same silent-failure theme as [the nmap scan](../Wazuh_nmap_scan/README.md), where no alert was generated because nothing was logged.

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Detected (100100), responded (100201) |

---

## Files

- [`custom-netsh-block.py`](custom-netsh-block.py) - Active Response script
- [`local_rules.xml`](../local_rules.xml) - rules 100100, 100201, 100202

---

## What this scenario demonstrates

- Automated response tied to a custom detection rule, with automatic expiry
- Debugging a response that reported success while doing nothing
- Handling a real gap between Wazuh's documented template and its runtime behaviour
- Recognising that response telemetry is a separate requirement from the response itself
