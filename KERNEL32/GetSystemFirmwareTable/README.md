# 🗂️ GetSystemFirmwareTable: 

## 🚀 Executive Summary
Ever wanted to ask Windows, “Hey, what kind of hardware are we really running on?” That’s what `GetSystemFirmwareTable` does. It can pull back juicy low level details straight from your system’s firmware. Things like manufacturer, BIOS version, serial numbers, and whether you’re sitting on a virtual machine. That’s great for IT inventory tools… but it’s also great for attackers who want to fingerprint a target, dodge sandboxes, or plan something nasty at the firmware level.

## 🔍 What is GetSystemFirmwareTable?
When you call `GetSystemFirmwareTable`, you give it a “provider signature” like 'ACPI' or 'RSMB', and it hands you a blob of data straight from the system’s firmware. This can include:

 - SMBIOS info (make, model, serial number, BIOS version)
 - ACPI tables (power management and device config data)

The output isn’t exactly bedtime reading. It’s raw bytes, but it’s packed with information that barely ever changes over the life of the machine. That stability makes it gold for profiling a system.

### Additional Info on ACPI and RSMB
 - `ACPI` tables are like the instruction manual your firmware gives the operating system. They spell out how the hardware is laid out, what devices exist, and how to manage power; straight from the BIOS or UEFI, no middleman.
 - `RSMB` is short for Raw SMBIOS. Ask for this table and Windows hands you the system’s hardware birth certificate including manufacturer, model, serial number, BIOS version; all straight from firmware, untouched and in its original binary glory.

`ACPI` is all about the playbook. It’s the firmware telling the operating system, “Here’s the map of the hardware, here’s how the parts talk to each other, and here’s when to dim the lights or cut the power.” It’s structural and operational info. The rules of the road for managing devices and power.

`RSMB`, on the other hand, is the roster. It’s the raw SMBIOS data, the who, what, and when of the machine: manufacturer, model, serial number, BIOS version. No instructions, no rules; just the hard facts about the hardware’s identity, right from firmware.

One’s the manual, the other’s the ID card. Both are gold for system profiling… but they tell very different parts of the story.

## 🚩 Why It Matters
Unlike OS level identifiers, firmware info survives most “wipe and reinstall” scenarios. If an attacker wants a stable fingerprint, this API is like a backstage pass to the hardware. It can reveal virtualization clues, unique IDs, and vendor fingerprints; all things that help decide whether to deploy a payload, hide, or run away.

## 🧬 How Attackers Abuse It
Here’s the playbook. Malware calls `GetSystemFirmwareTable` and grabs the raw SMBIOS data. Think of it as the system’s DNA profile. It then scans for telltale strings like “VMware,” “VirtualBox,” or “QEMU.” Those are giant neon signs that say, “You’re not on a real victim’s machine, you’re in a sandbox.” If it spots one, the malware can just… walk away. No errors, no fireworks, nothing to tip off the analyst. It simply exits like it was never there. This is classic antianalysis: avoid giving researchers any behavior to study, and dodge automated detonations in sandboxes.

It doesn’t stop there. Some malware uses the same firmware data to decide whether you’re the right target at all. If the manufacturer string says “Dell” and the operation is hunting only Lenovo hardware, the payload stays zipped. If it’s building persistence below the OS, that BIOS version number tells it exactly what it’s working with, whether it can safely flash a malicious image, or if it needs a different tool entirely. Antianalysis, victim selection, and precision targeting, all from a single API call.

## 🛡️ Detection Opportunities
Normal users and office software almost never need firmware tables. When you see them being accessed by something that just came out of an email attachment, that’s suspicious.
Keep an eye out for firmware API calls in processes spawned from scripts, Office macros, or known post exploitation frameworks. Like most of what we talk about in the Windows API Abuse Atlas, the context matters more than the call itself. Plenty of legit tools(inventory agents, hypervisor software) use this API every day.

Here are some sample YARA rules to detect suspicious use of `GetSystemFirmwareTable`:

See [GetSystemFirmwareTable.yar](./GetSystemFirmwareTable.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Pulling the 'RSMB' table and immediately checking for virtualization vendor strings. 
 - Quitting or switching payload behavior right after reading firmware info

## 🦠 Malware & Threat Actors Documented Abusing GetSystemFirmwareTable

### **Ransomware**
- Charon
- Medusa

### **Commodity Loaders & RATs**
- FudModule Rootkit
- Nidhogg Rootkit
- WhiskerSpy Backdoor

### **APT & Threat Actor Toolkits**
- Earth Kitsune
- Lazarus

### **Red Team & Open Source Tools**
- Master (C2 Framework)

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `GetSystemFirmwareTable`.

## 🧵 `GetSystemFirmwareTable` and Friends
`EnumSystemFirmwareTables` will tell you what table types are available before you fetch one.`GetFirmwareEnvironmentVariable` lets you read UEFI variables.`SetFirmwareEnvironmentVariable` lets you write them, but you’ll need high privileges (and possibly a fire extinguisher if you get it wrong).

## 📚 Resources
- [Microsoft Docs: GetSystemFirmwareTable](https://github.com/danafaye/WindowsAPIAbuseAtlas/tree/main/KERNEL32/GetSystemFirmwareTable)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!