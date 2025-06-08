# NtSetInformationThread

## 🚀 Executive Summary
**`NtSetInformationThread` abuse** is a subtle but effective way for attackers to mess with how threads behave — often to hide from debuggers or security tools. By setting certain thread attributes, malware can avoid being suspended, conceal itself from analysis, or tamper with execution in ways that aren’t always obvious. This API doesn’t get as much attention as some of the flashier techniques, but it shows up in real-world malware and red team tools for a reason. In this entry, we walk through how `NtSetInformationThread` is used for evasion, why it works, and how defenders can spot it.

## 🔍 What is NtSetInformationThread?
**`NtSetInformationThread` abuse** works because it gives attackers low-level control over how threads behave in a process. This API can change thread properties like hiding from debuggers, modifying execution states, or preventing a thread from being suspended. Tools like debuggers, sandboxes, and even some EDRs rely on predictable thread behavior to monitor suspicious activity. By quietly calling `NtSetInformationThread` with just the right parameters, malware can sidestep analysis, disrupt security tooling, and keep its execution path under the radar.

## 🚩 Why It Matters
- **Still flying under the radar:** `NtSetInformationThread` abuse isn’t as widely discussed as other evasion tactics, but it's quietly effective—and increasingly used.
- **Used for anti-analysis and evasion:** Attackers use this API to hide threads from debuggers, tamper with thread behavior, or prevent suspension, making malware harder to analyze or interrupt.
- **Flexible and low-noise:** With the right parameters, it lets malware evade detection without needing noisy hooks or injections—just a single stealthy API call.

## 🧬 How Attackers Abuse It

### 🛡️ Anti-Debugging
One of the most common abuses of `NtSetInformationThread` is using it with the `ThreadHideFromDebugger` (0x11) `THREAD_INFORMATION_CLASS`. This sets a flag in the thread's `ETHREAD` structure that tells user-mode debuggers to leave the thread alone. It doesn’t stop kernel-mode debuggers, but it’s enough to break tools like x64dbg or OllyDbg. Malware often uses this early in execution to frustrate reverse engineering and dynamic analysis.

### 🧬 Facilitating Injection
Attackers also use `NtSetInformationThread` to help with process injection techniques. After creating a remote or suspended thread—using `CreateRemoteThread`, `NtCreateThreadEx`, or similar—they'll immediately call `NtSetInformationThread` to modify properties like scheduling priority, affinity, or to hide the thread. This can make injected threads harder to spot in monitoring tools or avoid detection by user-mode hooks. Because the call is made directly to the native API, it often flies under the radar of higher-level security tooling.

## 🧵 Sample behavior
### Anti-Debugging Use
- Calls `NtSetInformationThread` with `ThreadHideFromDebugger` (`0x11`) early in execution.
- Targets threads within the malware’s own process to evade user-mode debuggers.
- Often precedes or coincides with anti-debugging checks or other evasive behavior.
- Typically observed in loader or initialization stages of malware.

### Injection Facilitation Use
- Calls `NtSetInformationThread` on remote or newly created threads after injection.
- Modifies thread properties such as priority, affinity, or hides the thread to evade detection.
- Happens shortly after thread creation (e.g., `CreateRemoteThread` or `NtCreateThreadEx`).
- Associated with process or thread injection techniques aiming to stealthily run malicious code.

## 🛡️ Detection opportunities

### 🔹 YARA

Here are some sample YARA rules to detect NtSetInformationThread misuse: 

see [NtSetInformationThread.yar](./NtSetInformationThread.yar).

Note: Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes — not for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🔸 Behavioral Indicators

Below are behavioral indicators that defenders can look for to spot the misuse of `NtSetInformationThread` in both anti-debugging and injection facilitation scenarios:

#### **Anti-Debugging**

- **Early call to `NtSetInformationThread`**: The function is invoked soon after process start, often before or alongside other anti-analysis checks.
- **Parameter value `0x11` (`ThreadHideFromDebugger`)**: The call uses this specific value for the `ThreadInformationClass` parameter, which is strongly associated with hiding threads from user-mode debuggers.
- **Target is a thread within the same process**: The thread handle passed typically refers to the malware’s own thread(s).
- **Followed or preceded by anti-debugging checks**: Calls to APIs like `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, or timing checks may occur in close proximity.
- **Absence of higher-level anti-debugging APIs**: The malware may avoid using more obvious anti-debugging APIs, relying instead on this lower-level native call.

#### **Facilitating Injection**

- **Thread creation in a remote process**: APIs such as `CreateRemoteThread`, `NtCreateThreadEx`, or similar are called to create a thread in another process.
- **Immediate or near-immediate call to `NtSetInformationThread`**: After thread creation, `NtSetInformationThread` is called on the new thread handle.
- **Modification of thread properties**: The function may be used to set properties like priority, affinity, or to hide the thread (`0x11`), making injected threads less visible to monitoring tools.
- **Sequence with memory manipulation APIs**: The behavior is often observed alongside calls to `VirtualAllocEx`, `WriteProcessMemory`, or similar APIs used for code injection.
- **Target is a remote thread**: The thread handle passed to `NtSetInformationThread` refers to a thread in another process, not the malware’s own process.

**In both cases, defenders should look for:**
- Unusual or unexplained use of `NtSetInformationThread`, especially with the `0x11` parameter.
- Sequences where thread creation, memory allocation, and thread hiding occur together.
- Use of native API calls that bypass higher-level Windows APIs, which may indicate attempts to evade detection or analysis.

## 🦠 Malware & Threat Actors Documented Abusing [Function/Technique Name] Patching

### **Ransomware**

### **Commodity Loaders & RATs**

### **APT & Threat Actor Toolkits**

### **Red Team & Open Source Tools**

## 🧵 `[Function/Technique Name]` and Friends

## 📚 Resources 