# 🛠️ DnsQuery: Name Resolution or Network Obfuscation?

## 🚀 Executive Summary
`DnsQuery` is a deceptively routine API with outsized potential for abuse. While it plays a critical role in legitimate name resolution, its ability to query arbitrary DNS record types especially TXT and target custom DNS servers makes it a prime candidate for stealthy command-and-control (C2) activity. Malware authors increasingly turn to `DnsQuery` to exfiltrate data, stage payloads, and evade traditional network monitoring, all under the guise of normal DNS traffic. Its presence alone isn’t suspicious, but its context often is. This entry explores how attackers weaponize a seemingly benign API to tunnel signals through infrastructure defenders often overlook.

## 🔍 What is DnsQuery?
`DnsQuery` is a user mode Windows API that allows applications to perform DNS lookups, translating human readable domain names (like example.com) into IP addresses the system can route to. It supports querying various DNS record types (A, AAAA, TXT, MX, others) and can resolve names using either the system configured DNS servers or custom ones supplied by the caller. `DnsQuery` is actually a common name for three function variants: `DnsQuery_A` (ANSI), `DnsQuery_W` (wide/Unicode), and `DnsQuery_UTF8`. These exist to support different character encodings based on the calling application's needs, something especially relevant for cross-language or internationalized software. Legitimately, this API powers everything from browsers fetching websites to email clients resolving mail servers. It's part of the `dnsapi.dll` library and offers more granular control than higher-level functions like getaddrinfo, making it a go-to for developers building network-aware applications, diagnostic tools, or custom DNS clients.

## 🚩 Why It Matters
While `DnsQuery` is a routine part of name resolution on Windows, its flexibility makes it particularly interesting. Unlike high level abstractions, `DnsQuery` gives callers direct access to query specific record types, specify custom flags, and even bypass normal resolver behavior. This low level control opens the door to behaviors that deviate from expected patterns, like queries to unexpected record types, resolution attempts against arbitrary DNS servers, or usage outside typical application contexts. When observed in unusual processes or at odd execution times, its presence can signal more than just a routine lookup. Understanding how and when this API shows up can help separate noise from signal.

## 🧬 How Attackers Abuse It
Malware leverages `DnsQuery` to blend command-and-control (C2) traffic into the background noise of normal system activity. By querying TXT, CNAME, or even A records for attacker controlled domains, malware can receive instructions, download payloads, or exfiltrate data; all without establishing direct socket based connections. TXT records are a particular favorite, as they allow arbitrary strings to be embedded in DNS responses, making them perfect for hiding C2 commands, staging shellcode, or delivering next-stage payloads. Some samples rotate subdomains or embed outbound data within query names themselves, fragmenting exfiltration across multiple lookups. Others abuse the API’s ability to target nonstandard DNS servers, using hardcoded IPs to route queries outside the enterprise perimeter. Since DNS is foundational to system operation, malicious use of `DnsQuery` often hides in plain sight, making it a favored technique for stealthy implants and beaconing backdoors alike.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `DnsQuery`:

See [DnsQuery.yar](./DnsQuery.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Like so many of the other APIs we've covered, detection of `DnsQuery` abuse starts with identifying what shouldn't be happening. Most legitimate applications using `DnsQuery` follow predictable patterns. They resolve common record types (A, AAAA, MX) against trusted DNS servers, and typically do so from user-facing processes like browsers, email clients, or system services. Deviations from this baseline are where the signal lives. **Look for unusual record types like TXT or NULL being queried by background or unsigned binaries, processes issuing high volumes of requests to untrusted domains, or those specifying hardcoded DNS servers rather than using system defaults.** Correlating process lineage and network behavior is key. `DnsQuery` abuse often surfaces in parent-child chains involving LOLBins (like rundll32.exe) or in conjunction with encoded DNS traffic. If telemetry allows, flagging rare uses of `dnsapi.dll` in non-standard processes or frequency anomalies in DNS resolution APIs can help identify implants beaconing via DNS or staging payloads in TXT records.

### 🔐 Note on Encrypted DNS
Although `DnsQuery` does not directly support DNS over HTTPS (DoH) or DNS over TLS (DoT), modern Windows configurations may transparently route system DNS queries through encrypted channels if DoH is enabled. This can reduce visibility into DNS traffic at the network layer, even when the underlying API call remains the same. Defenders relying solely on plaintext DNS telemetry may miss malicious lookups, especially when combined with local resolver manipulation or custom DNS servers.

## 🦠 Malware & Threat Actors Documented Abusing DnsQuery

### **Ransomware**
 - BlackBasta

### **Commodity Loaders & RATs**
 - IcedId
 - Rovnix
 - Sysjoker

### **APT & Threat Actor Toolkits**
 - APT18
 - OilRig

### **Red Team & Open Source Tools**
 - Cobalt Strike

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `DnsQuery`.

## 🧵 `DnsQuery` and Friends
`DnsQuery` sits among a family of Windows APIs that perform name resolution, each with varying levels of abstraction and control. Higher level functions like `getaddrinfo`, `GetHostByName`, and `GetNameInfoW` often wrap or indirectly rely on `DnsQuery` under the hood, but abstract away record type handling and resolver configuration. On the lower end, raw socket use (like with `WSASocket` and `sendto`) enables fully custom DNS implementations, often seen in malware attempting to evade system resolvers altogether. In practice, `DnsQuery` is often paired with APIs like `InternetOpenUrl`, `HttpSendRequest`, or `WinHttpGetProxyForUrl` when malware mixes DNS beaconing with webbased payload retrieval. Observing DnsQuery in proximity to process injection (`CreateRemoteThread`, `VirtualAllocEx`) or obfuscation routines (`CryptStringToBinary`, `RtlDecompressBuffer`) can also be an early indicator of staged or stealthy C2 workflows.

## 📚 Resources
- [DomainTools.com: Malware in DNS](https://dti.domaintools.com/malware-in-dns/)
- [Microsoft Docs: DnsQuery](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsquery_utf8)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!