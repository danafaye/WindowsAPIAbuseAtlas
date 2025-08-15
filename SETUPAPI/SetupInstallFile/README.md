# 🛠️ SetupInstallFile: 

## 🚀 Executive Summary
`SetupInstallFile` might not be the flashiest API in the Windows lineup, but it quietly sits in the Setup API family, waiting for anyone (legitimate installer or malicious actor) to call on it to copy a file from one location to another with all the privileges and bells and whistles you’d expect from the system’s own installer logic. For defenders, this is both a red flag and a headache, because malicious use often blends in with normal installation activity. For attackers, it’s a convenient way to sidestep restrictions, replace or add files in protected areas, and even plant malicious payloads while looking “official.”

## 🔍 What is SetupInstallFile?
At its core, `SetupInstallFile` is a Windows Setup API function designed to copy a file from a source (like an installation package) to a target directory on the system. It handles the details for you, like the destination creation, file attribute preservation, overwrite behavior, and integration with the broader setup transaction. It’s meant to be part of driver and application installation routines, particularly in INF driven setups, but the call itself is pretty open ended. The function signature allows you to specify exactly where the file should go and whether it should overwrite existing files. If you’ve got the right privileges, `SetupInstallFile` can put files in places that normal copy functions might not be allowed to touch.

## 🚩 Why It Matters
Any API that can **place or overwrite files in privileged locations** is a potential gift to an attacker. `SetupInstallFile` lives in the `setupapi.dll` library, which is loaded by default in many installation contexts, and often runs with elevated privileges. This means a malicious payload can be delivered and staged without calling the usual suspects like `CopyFile` or `MoveFileEx`, which are more heavily monitored by EDRs. On a forensic timeline, malicious calls to `SetupInstallFile` can hide in a sea of legitimate installer activity, making detection trickier unless you know exactly what to look for.

## 🧬 How Attackers Abuse It
When malware authors or red teamers get creative, `SetupInstallFile` becomes a surgical tool for dropping or replacing files in sensitive areas such as `System32` or driver directories. Because it’s part of a trusted API set used by Windows setup processes, calls to it can blend into normal driver installation logs. Attackers can use it to:

 - Install a malicious DLL or EXE in a location where it will be executed by a legitimate process.
 - Replace an existing binary with a trojanized version, achieving persistence or privilege escalation.
 - Deploy kernel drivers under the guise of a legitimate setup operation.

It’s especially effective when paired with other Setup API calls that stage INF files, because it allows the attack to mimic a standard driver install process from start to finish.

## 🛡️ Detection Opportunities
Monitoring for `SetupInstallFile` usage outside of known installation processes is the big win here. Pay attention to `setupapi.dev.log` entries that don’t align with legitimate installs, especially those involving sensitive directories or unexpected source paths (like temporary folders, user profile paths). API call telemetry from EDRs can also surface anomalous `SetupInstallFile` invocations from processes that shouldn’t normally be installing anything ... think browsers, office applications, or scripts. Correlating this with unusual file writes, process injections, or driver loads can narrow detection without creating excessive noise.

Here are some sample YARA rules to detect suspicious use of `SetupInstallFile`:

See [SetupInstallFile.yar](./SetupInstallFile.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
Suspicious behaviors might include:

 - Calls to `SetupInstallFile` from processes that are not known installers.
 - File destinations in System32, drivers, or other protected paths during noninstallation events.
 - Overwrites of existing signed binaries with unsigned versions.
 - Activity preceded by the extraction of an INF file from an unusual source archive.
 - Setup API calls that occur shortly before a suspicious driver or service installation.

## 🦠 Malware & Threat Actors Documented Abusing SetupInstallFile
So here’s the deal: as of right now, there aren’t any publicly documented malware families where a researcher has stood up and said, “Yep, this one calls `SetupInstallFile`.” At least that I could find ... That’s not to say it doesn’t happen; just that nobody’s put it in writing where we can cite it.

What I did find, over and over, is malware hiding behind installer style execution flows, which is exactly the camouflage `SetupInstallFile` thrives in. Families like *Cerber*, *Gamarue*, *Kovter*, and *ZCrypt* have been spotted wrapping their payloads inside NSIS or other legitimate installer frameworks. Once in that installer context, it’s trivial for an attacker to call trusted setup APIs to drop files into protected locations whether they’re overwriting binaries, planting payloads in System32, or staging malicious drivers.

In other words: even if we can’t point to a headline case of “APT-X abused SetupInstallFile,” the TTP is alive and well. The function’s role in the trusted Windows Setup API family makes it an attractive dropper helper for anyone who wants to look like a legitimate install while quietly slipping in something toxic.

## 🧵 `SetupInstallFile` and Friends
`SetupInstallFile` often shows up in the company of other Setup API calls like `SetupCopyOEMInf`, `SetupInstallServicesFromInfSection`, and `SetupDiCallClassInstaller`. Together, they can stage and execute full driver or application installs. From an attacker’s perspective, chaining these functions makes the malicious operation look even more like a legitimate hardware setup event. Defenders should consider this API family as a whole when hunting for abuse.

## 📚 Resources
- [Microsoft Docs: SetupInstallFile](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupinstallfilew)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)
- [Windows API Abuse Atlas: InstallHinfSection](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/SETUPAPI/InstallHinfSection)

> Open a PR or issue to help keep this list up to date!