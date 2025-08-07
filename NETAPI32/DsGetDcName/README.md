# 🔔 DsGetDcName: Active Directory Doorbell

## 🚀 Executive Summary
`DsGetDcName` is a Windows API function that helps applications locate domain controllers (DCs) in Active Directory environments. While it plays a crucial role in enterprise authentication and directory services, adversaries often leverage it during internal reconnaissance to map domain structures, identify key infrastructure, and prepare for lateral movement.

Knowing when and why this function gets called can help defenders distinguish normal domain aware activity from adversary enumeration tactics.

## 🔍 What is DsGetDcName?
`DsGetDcName` is part of the Netlogon API and is used to retrieve information about a domain controller (DC) in a specified domain. A DC is a server that responds to security authentication requests and stores Active Directory (AD) data. This function returns details such as the name, address, and capabilities of a DC, including whether it's a global catalog server or supports directory services.

Its prototype in C looks like this:

```c
DWORD DsGetDcName(
  LPCWSTR ComputerName,
  LPCWSTR DomainName,
  GUID    *DomainGuid,
  LPCWSTR SiteName,
  ULONG   Flags,
  PDOMAIN_CONTROLLER_INFO *DomainControllerInfo
);
```
Flags passed to this function can modify behavior like, asking for a writable DC, avoiding cached responses, or preferring global catalog servers.

## 🚩 Why It Matters
Domain controllers are the nerve centers of Windows enterprise networks. Knowing where they are and what roles they serve is crucial for attackers planning privilege escalation, lateral movement, or exfiltration operations.

The significance of `DsGetDcName` lies in its ability to silently map an enterprise’s Active Directory infrastructure without touching endpoints in ways that trigger traditional security controls. It’s not noisy, doesn’t require admin rights, and its use can blends in with normal domain aware application behavior.

## 🧬 How Attackers Abuse It
Adversaries use `DsGetDcName` to:
 - Identify the closest or most suitable domain controller.
 - Confirm domain membership and existence of trusted domains.
 - Determine if a domain controller is also a global catalog server.
 - Dynamically adapt tooling to match the AD environment during automated operations.

Some common abuse scenarios:
 - **Post compromise enumeration**: After obtaining access to a domain-joined system, an attacker may use DsGetDcName to identify infrastructure worth targeting (e.g., global catalog servers or writable DCs).
 - **C2 flexibility**: Malware and post exploitation frameworks may call this function to adapt to different AD environments or to automate discovery without hardcoded infrastructure paths.
 - **Red team tooling**: Tools like Cobalt Strike or custom PowerShell scripts may rely on DsGetDcName to map trust relationships or domain hierarchies stealthily.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `DsGetDcName`:

See [DsGetDcName.yar](./DsGetDcName.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Execution of unsigned binaries that use LOLBins or custom payloads that import or dynamically resolve `DsGetDcName`.
 - PowerShell or .NET assemblies performing domain controller discovery without accompanying enterprise service context.
 - `DsGetDcName` usage followed by, plus LDAP queries to domain controllers.
 - `DsGetDcName` call followed by `NetServerEnum`, `DsEnumerateDomainTrusts`, or `NetWkstaGetInfo`
 - `DsGetDcName` followed by attempts to connect to ports 88, 389, or 445 on discovered DCs

Tip: Pair API call monitoring with context, which process used it, at what time, and whether domain discovery follows initial access.

## 🦠 Malware & Threat Actors Documented Abusing DsGetDcName

### **Ransomware**
 - Ryuk/Conti

### **Commodity Loaders & RATs**
 - Qakbot

### **APT & Threat Actor Toolkits**
 - APT29

### **Red Team & Open Source Tools**
 - Cobalt Strike
 - SharpHound

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `DsGetDcName`.

## 🧵 `DsGetDcName` and Friends

🧵 DsGetDcName and Friends
Some APIs work in concert with or provide alternatives to `DsGetDcName`:

 - `DsGetSiteName`: Retrieves the site name associated with a computer often used alongside `DsGetDcName` to narrow search scope.
 - `DsEnumerateDomainTrusts`: Identifies trusted domains which is useful after a DC is located.
 - `NetGetJoinInformation`: Checks if a machine is joined to a domain, often a precursor to `DsGetDcName`.
 - `DsBind`, `LDAPBind`, or `NetServerEnum`: Often follow `DsGetDcName` in adversary workflows for further domain or server interrogation.
 
 Think of `DsGetDcName` as a doorbell to the Active Directory neighborhood. Once an attacker rings it, they’ll likely start exploring the houses inside.

## 📚 Resources
- [Microsoft Docs: DsGetDcName](https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamea)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!