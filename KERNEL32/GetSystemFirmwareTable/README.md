# 🛠️ GetSystemFirmwareTable: 

## 🚀 Executive Summary
Ever wanted to ask Windows, “Hey, what kind of hardware are we really running on?” That’s what `GetSystemFirmwareTable` does. It can pull back juicy low level details straight from your system’s firmware. Things like manufacturer, BIOS version, serial numbers, and whether you’re sitting on a virtual machine. That’s great for IT inventory tools… but it’s also great for attackers who want to fingerprint a target, dodge sandboxes, or plan something nasty at the firmware level.

## 🔍 What is GetSystemFirmwareTable?
When you call `GetSystemFirmwareTable`, you give it a “provider signature” like 'ACPI' or 'RSMB', and it hands you a blob of data straight from the system’s firmware. This can include:

 - SMBIOS info (make, model, serial number, BIOS version)
 - ACPI tables (power management and device config data)

The output isn’t exactly bedtime reading. It’s raw bytes, but it’s packed with information that barely ever changes over the life of the machine. That stability makes it gold for profiling a system.

 - `ACPI` tables are data and structuresthat the firmware (BIOS/UEFI) provides to the operating system.
 - `RSMB` or Raw System Management BIOS: SMBIOS firmware table provider used in most Windows systems.

## 🚩 Why It Matters
Unlike OS level identifiers, firmware info survives most “wipe and reinstall” scenarios. If an attacker wants a stable fingerprint, this API is like a backstage pass to the hardware. It can reveal virtualization clues, unique IDs, and vendor fingerprints; all things that help decide whether to deploy a payload, hide, or run away.

## 🧬 How Attackers Abuse It
Here’s the playbook. Malware runs `GetSystemFirmwareTable`, pulls down the SMBIOS data, and looks for strings like “VMware,” “VirtualBox,” or “QEMU.” If it sees one, it might assume it’s in a sandbox and exit quietly. Other times, it uses this info to profile the victim’s hardware, making sure the payload is only deployed to certain machines or to prep for firmware level persistence by confirming the exact BIOS version.

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

### **Commodity Loaders & RATs**

### **APT & Threat Actor Toolkits**

### **Red Team & Open Source Tools**

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `GetSystemFirmwareTable`.

## 🧵 `GetSystemFirmwareTable` and Friends
`EnumSystemFirmwareTables` will tell you what table types are available before you fetch one.`GetFirmwareEnvironmentVariable` lets you read UEFI variables.`SetFirmwareEnvironmentVariable` lets you write them, but you’ll need high privileges (and possibly a fire extinguisher if you get it wrong).

## 📚 Resources
- [Microsoft Docs: GetSystemFirmwareTable]()
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!