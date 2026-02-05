**SSH Credential Harvesting Investigation (Trojanized libssh)**
**Overview**

A hands-on Digital Forensics & Incident Response (DFIR) investigation of a compromised Linux host, performed entirely using native command-line tools (“living off the land”).  

This project documents the discovery and reverse engineering of an SSH credential harvesting attack involving a trojanized `libssh.so`, including log analysis, malicious shared library identification, stack memory inspection, credential exfiltration tracing, and threat campaign attribution.

The analysis covers:

SSH brute force vs successful authentication

Identification of a trojanized binary

Reverse engineering of the malicious shared object

Credential exfiltration logic

Stack memory allocation analysis

Threat infrastructure attribution

This lab simulates a realistic post-compromise DFIR workflow combining log analysis, malware reverse engineering, and threat intelligence correlation.

**Objectives**

Identify attacker IP addresses and successful logins

Locate the malicious binary/library

Extract cryptographic hashes

Reverse engineer credential exfiltration logic

Determine stack allocation used for payload construction


**Environment**

Ubuntu Linux

OpenSSH

auth.log

objdump, strings, grep, stat, md5sum

Custom trojanized /usr/lib/libssh.so

**Phase 1 — SSH Log Analysis**
Failed Login Attempts

Multiple brute-force attempts were observed:

Failed password for invalid user admin from 188.186.59.123


These were noise and not part of the successful compromise.

**Successful Authentication**

Valid logins were identified via:

'grep Accepted /var/log/auth.log*'


**Key result:**

Accepted password for dev1 from 188.241.80.65


This IP represents the attacker’s successful access.

**Phase 2 — Identifying the Trojanized Library**

Running process inspection:

'lsof -p <sshd_pid>'


Revealed:

'/usr/lib/libssh.so'


This library does not belong in the default OpenSSH execution path.

Further confirmation:

'dpkg -V openssh-client'


Returned verification failures on /usr/bin/ssh, confirming binary tampering.

**Phase 3 — Malicious Library Hash**

The malicious shared object:

'/usr/lib/libssh.so'


MD5 extracted via:

'md5sum /usr/lib/libssh.so'


(Recorded separately in lab notes.)

**Phase 4 — Reverse Engineering Credential Theft**

Disassembly:

'objdump -d -M intel /usr/lib/libssh.so > libssh.asm'


Key exported functions discovered:

'send_credential'
'send_credential_thread'


These functions handle credential collection and transmission to attacker infrastructure.

**Stack Allocation Analysis**

Inside send_credential_thread:

'sub rsp,0x850'

Result:
0x850 = 2128 bytes


2128 bytes allocated on the stack for request payloads

This memory region is used to construct credential exfiltration data before network transmission.

**Credential Exfiltration**

The malware uses libcurl APIs:

curl_easy_setopt

httpost

socket callbacks

Credential format observed:

credential=%s


Data is sent over HTTPS to attacker-controlled infrastructure.

**IP Obfuscation**

Embedded IP addresses inside the shared object were encoded using:

XOR

Decoded strings revealed external infrastructure endpoints.

**Threat Intelligence Correlation**

All attacker IPs used in this lab were previously observed in a real-world campaign targeting:

Cambodia

This was determined through infrastructure reuse analysis across multiple incidents.

**Key Takeaways**

Credential harvesting can be hidden behind legitimate binaries

Shared library hijacking is an effective persistence mechanism

SSH brute-force noise can mask successful compromise

Reverse engineering is often required when logs alone are insufficient

Threat attribution frequently depends on infrastructure reuse

Native Linux tools are sufficient for deep DFIR when used methodically

**Skills Demonstrated**

Linux Incident Response

SSH log analysis

Shared library hijacking detection

Malware reverse engineering (objdump / assembly)

Stack memory inspection

Credential exfiltration tracing

Threat hunting & attribution

Living-off-the-land forensic techniques
