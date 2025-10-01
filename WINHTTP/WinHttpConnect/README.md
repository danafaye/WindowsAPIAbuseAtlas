# 🔌 WinHttpConnect

## 🚀 Executive Summary
`WinHttpConnect` is the little backstage door that network enabled malware loves to slip through when it wants to talk to the internet without bothering the user interface. In plain English: it’s the call a program uses to establish a connection handle to a remote HTTP(S) server after it’s created a `WinHTTP` session. Attackers lean on it for command and control chatter, payload downloads, and quiet exfiltration because it’s a documented, supported API that plays nicely with Windows networking stacks and can be called from services and headless processes. 

## 🔍 What is WinHttpConnect?
`WinHttpConnect` is part of the `WinHTTP` family: after a program calls `WinHttpOpen` to create a `WinHTTP` session (which describes how the app will talk to the network), it calls `WinHttpConnect` to obtain a connection handle bound to a specific server name and port. That handle is then used by subsequent calls like `WinHttpOpenRequest`, `WinHttpSendRequest`, and `WinHttpReceiveResponse` to actually perform HTTP operations. Conceptually it’s a lightweight way for a process or service to say “I want to talk to example.com:443” and get back a handle to route all the following HTTP plumbing through. Because it’s synchronousish and doesn’t require a user facing browser, it’s a favorite for background network activity.

## 🚩 Why It Matters
`WinHttpConnect` matters because it’s a sanctioned, well supported API for making HTTP(S) connections from native code. Exactly the kind of tool attackers prefer when they want to blend in. Legit apps, updaters, telemetry agents, and many services use `WinHTTP`, so a call to `WinHttpConnect` alone is not suspicious. The problem for defenders is that the same call lets malicious code reach out to C2 servers, fetch second stage payloads, or quietly slide data out to a remote host, all without popping a window or invoking a user’s browser. Because `WinHTTP` can be used in service contexts and configured to use system or custom proxy settings, adversaries exploit it to avoid simpler network detection heuristics that focus only on browsers or obvious web clients. Even worse, `WinHTTP` traffic can easily mimic user generated internet traffic; it the same ports, TLS handshakes, SNI, and configurable headers (including common User Agent strings and cookie handling), so malicious connections can hide in plain sight among normal app updates and background syncs unless you look at context, frequency, and payload patterns.

## 🧬 How Attackers Abuse It
Attackers call `WinHttpConnect` as the opening move in a scripted network conversation that often looks extremely polite on the wire: create a session, connect to server, open a request, send, receive. The romance ends when those polite requests are delivering encrypted stagers, beacon payloads, or compressed exfiltration bundles. Malware authors embed server hostnames (or resolve them at runtime), call `WinHttpConnect` to bind to the remote host and port, and then proceed to `WinHttpOpenRequest` and `WinHttpSendRequest` to exchange data. Sometimes the connection is to a literal IP; sometimes it’s to a domain fronted by CDN infrastructure, and sometimes it’s tunneled through proxies or abused with odd User-Agent strings and custom headers to imitate legitimate traffic. Red teams use the same sequence to stage payloads or test detection. The result is identical: a process that isn’t a browser makes HTTP(S) calls using `WinHTTP` primitives, often repeatedly, on schedule or in response to local triggers.

## 🛡️ Detection Opportunities
Detecting malicious use of `WinHttpConnect` is a story of context, correlation, and a little bit of impatience: the API call by itself is common and noisy, so the useful signals come from how and when it’s used. Monitor which processes are calling `WinHTTP` APIs, and watch for **non-browser** executables creating sessions and immediately establishing connections to unusual servers or high frequency endpoints. Correlate those API calls with network telemetry: does the process have a parent that makes no sense for network activity, or is it a living in memory loader that previously created suspicious file mappings? 

Look for `WinHTTP` calls where SNI, certificate chains, or TLS parameters are inconsistent with known good patterns for the host being contacted. Pay attention to odd User-Agent strings, repeated small POSTs that resemble beacons, or large outbound responses that look like a payload download. 

Also, endpoint instrumentation that logs API names, parameters (like the server name and port passed to `WinHttpConnect`), return handles, and subsequent send/receive calls will make it possible to stitch a narrative of a suspicious network workflow. Finally, cross check with proxy logs and DNS records; a process that calls `WinHttpConnect`("weird-domain.tld", 443) and then resolves dozens of domain variants or rotates IPs is giving you a gift-wrapped lead.

Here are some sample YARA rules to detect suspicious use of `WinHttpConnect`:

See [WinHttpConnect.yar](./WinHttpConnect.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
When WinHTTP is being abused, the surrounding behavior is usually what trips defenders. A process that silently spins up a `WinHTTP` session, calls `WinHttpConnect` to a host that never served the same process before, opens an HTTP request immediately after, then downloads and executes or maps the received payload, is a canonical pattern. 

Another tell is repetitive short POST requests that are time-sliced like heartbeats, with occasional larger GETs to pull configuration or modules. 

If the host is contacted over HTTPS but presents certificate chains that don’t match the expected issuer or exhibit frequent certificate changes, that’s suspicious. 

And of course, processes launched from temporary directories, living in memory loaders that show no disk based persistence but talk over `WinHTTP`, and utilities that alter proxy related `WinHTTP` options are all behavioral flags worth hunting. 

A red-team give-away is when standard command line tools or signed system binaries are used as loaders and suddenly start calling `WinHTTP` functions; defenders should treat that as a strong signal that the process is being repurposed.

## 🦠 Malware & Threat Actors Documented Abusing WinHttpConnect

### **Ransomware**
 - Diavol
 - Phobos
 - PrincessLocker

### **Commodity Loaders & RATs**
 - AsyncRAT
 - QakBot
 - Vidar

### **APT & Threat Actor Toolkits**
 - Cozy Bear
 - Sandworm
 - Turla

### **Red Team & Open Source Tools**
 - Covenant
 - Impacket
 - Havoc C2

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `WinHttpConnect`.

## 🧵 `WinHttpConnect` and Friends
`WinHttpConnect` almost always appears as part of a WinHTTP sequence, so it’s useful to consider the surrounding calls for a fuller picture. 

  - `WinHttpOpen` creates the session attributes and options
  - `WinHttpOpenRequest` constructs the HTTP request object referencing verbs and resource paths
  - `WinHttpSendRequest` pushes the request on the wire
  - `WinHttpReceiveResponse` reads back the server’s response
  - `WinHttpCloseHandle` tidies up when the caller is done
  
  There are also helpful siblings, such as `WinHttpSetOption` for toggling proxy or TLS behaviors, `WinHttpQueryHeaders` for inspecting server headers, and the legacy `InternetConnect`/`HttpOpenRequest` family from `WinINet` that sometimes appears in mixed stacks. Hunters should track the entire chain. A lonely `WinHttpConnect` without follow ups is weak evidence, but a `WinHttpConnect` that is immediately followed by an `WinHttpSendRequest` with a suspicious Host header or payload is the pattern that turns curiosity into a high confidence detection.

## 📚 Resources
- [Microsoft Docs: WinHttpConnect](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!