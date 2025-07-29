# 🎚️ NtSetDebugFilterState: Debug Volume Knob

## 🚀 Executive Summary
`NtSetDebugFilterState` is the Windows kernel’s “volume knob” for debug messages. It lets developers turn up or silence specific types of system chatter during troubleshooting. While handy for legit debugging, threat actors have figured out how to use this API to mute the noise that might give away their shady kernel level moves. It’s not a common trick in the malware playbook, but when it shows up, it’s a red flag for sophisticated attackers trying to sneak under the radar by tweaking the debug output behind the scenes.

## 🔍 What is NtSetDebugFilterState?
`NtSetDebugFilterState` is a native API that allows fine grained control over the kernel debugger’s filtering of debug output. Its intended purpose is to enable or disable specific debug message categories or levels, helping developers tailor the volume and type of debug information they receive during system or driver debugging sessions. By adjusting these filters, developers can reduce noise and focus on relevant diagnostics. This function is primarily leveraged by debugging tools or system components involved in low level troubleshooting and is rarely called by typical user mode applications.

## 🚩 Why It Matters
While `NtSetDebugFilterState` may seem innocuous and primarily useful for legitimate debugging, its presence and use in unexpected contexts can signal attempts to manipulate system debug settings; potentially to suppress or alter debug output during malicious activity. Attackers may leverage this API to evade detection by security tools that rely on debug information or to interfere with forensic analysis. Monitoring calls to `NtSetDebugFilterState` can therefore provide valuable insight into adversaries trying to obscure their actions or disrupt normal debugging and monitoring workflows.

## 🧬 How Attackers Abuse It
`NtSetDebugFilterState` is abused by malware to alter kernel debugger filter settings, suppressing specific debug output categories or levels. By reducing debug verbosity, adversaries limit the visibility of their kernel mode activities to debugging and monitoring tools. This can obstruct detection of suspicious behaviors such as driver loading, kernel hooks, or anomalous thread operations. Used primarily by advanced threat actors, this API manipulation serves as an antidebugging and antiforensic technique to frustrate analysis and evade security monitoring. Although uncommon in commodity malware, its invocation should be considered indicative of attempts to manipulate low level debug information and avoid detection.

`NtSetDebugFilterState` takes two key parameters: a filter class and a filter level. The filter class specifies a category of debug messages (like system, driver, or IO manager), while the filter level determines the verbosity or severity of messages to be enabled or disabled. Common filter classes include:

   FLT_SYSTEM: Controls debug messages related to core system events like process and thread creation.
   FLT_DRIVER: Manages debug output from device drivers, including driver load and unload notifications.
   FLT_IO: Covers input/output manager debug messages that can reveal file, network, or device activity.

By setting these filters to low or zero levels, attackers mute debug output that would normally surface suspicious driver behavior, thread injections, or anomalous IO operations. For example, disabling `FLT_DRIVER` messages can hide the loading of malicious kernel drivers. Adjusting `FLT_SYSTEM` filters may obscure thread or process manipulations often used in advanced persistence techniques.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `NtSetDebugFilterState`:

See [NtSetDebugFilterState.yar](./NtSetDebugFilterState.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
   Almost any calls to `NtSetDebugFilterState` outside of known debugging tools or legitimate system processes
   Changes to debug filter settings that reduce or silence debug output related to kernel events, such as driver loads, thread creation, or IO operations
   Timing of calls coinciding with suspicious activities like driver injection, kernel module loading, or process/thread manipulation
   Presence of other antidebugging or antiforensic techniques employed alongside filter manipulation
   Use of obscure or undocumented parameters to selectively disable verbose debug messages while maintaining system stability
    Correlate usage of this API with other kernel level activities like driver loading, thread manipulation, or code injection to understand the scope of stealth techniques

## 🦠 Malware & Threat Actors Documented Abusing NtSetDebugFilterState
Abuse of `NtSetDebugFilterState` remains relatively uncommon and is typically observed in high sophistication threat actors or specialized tooling, due to its narrow applicability and the specific knowledge required to effectively manipulate kernel debug filters.

### **Ransomware**
   DarkSide
   REvil

### **Commodity Loaders & RATs**
   AsyncRAT
   QuasarRAT

### **APT & Threat Actor Toolkits**
   APT29
   APT41

### **Red Team & Open Source Tools**
   Cobalt Strike
   Process Hacker

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `NtSetDebugFilterState`.

## 🧵 `NtSetDebugFilterState` and Friends
Several other native APIs provide functionality related to kernel debugging and diagnostic control, which adversaries may also abuse to evade detection. For example, `NtSetDebugFilterState` is often used in conjunction with calls like `NtCreateDebugObject` or `NtOpenDebugObject`, which establish or open a handle to a kernel debug object required for modifying debug filters. Additionally, `DbgSetDebugFilterState`, a user mode counterpart with overlapping capabilities, may be leveraged. Functions such as `NtSetInformationThread` with the `ThreadHideFromDebugger` information class can be used to hide threads from debuggers, while `NtQueryDebugFilterState` allows querying of current debug filter settings. Together, these APIs provide multiple vectors for attackers to manipulate system debug behavior, complicate forensic analysis, and hinder security monitoring. Understanding the interplay between these functions is essential for comprehensive detection of kernel level anti debugging techniques.

## 📚 Resources
  [anti debug.checkpoint.com](https://anti debug.checkpoint.com/techniques/misc.html)
  [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!