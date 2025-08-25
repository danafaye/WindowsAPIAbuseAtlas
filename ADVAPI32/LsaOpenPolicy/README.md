# 🛠️ LsaOpenPolicy

## 🚀 Executive Summary
`LsaOpenPolicy` is a door opener. Literally. It’s the API call that gets you into the Local Security Authority (LSA) policy object, which then lets you query or modify local security settings. Normally it’s used by administrators or services that need to check domain trust info, audit policies, or account rights. But attackers? They love it because once you’ve got a handle from `LsaOpenPolicy`, you can start digging into sensitive secrets like service account credentials, policy information, or even manipulate privileges. Think of it as the master key to a whole section of Windows security internals.

## 🔍 What is LsaOpenPolicy?
At its core, `LsaOpenPolicy` is a function in Advapi32.dll that lets software open a handle to the local or a remote machine’s LSA Policy object. The handle it returns is what unlocks a bunch of other powerful LSA functions. Admin tools use it all the time for things like reading audit policy or managing trust relationships. Attackers? They use it for credential dumping and persistence.

The function takes in a target system name, a desired access level, and spits out a handle. If that access mask asks for full rights, you’ve just handed someone the keys to a very sensitive part of the system.

## 🚩 Why It Matters
Once you can open the policy object, you’re not just playing in the shallow end anymore. You can start grabbing secrets stored in LSA, enumerate trust paths for lateral movement, and even change what accounts are allowed to do on the system. It’s rarely the final step. It’s the enabler. Think of it as the pivot point between having basic access and taking control of security-critical information.

## 🧬 How Attackers Abuse It
Attackers typically don’t call LsaOpenPolicy` just to feel accomplished. They call it because it’s the required first step to use other juicy functions like `LsaRetrievePrivateData` or `LsaAddAccountRights`. For example, credential dumping tools like Mimikatz use this call to get their initial policy handle before they start pulling secrets out of memory. Others abuse it to enumerate trust relationships across domains, which helps map the environment for further compromise.

On its own, `LsaOpenPolicy` doesn’t steal anything. It just unlocks the ability to do so. That’s why defenders need to pay attention to what follows it.

## 🛡️ Detection Opportunities
Here are some sample YARA rules to detect suspicious use of `LsaOpenPolicy`:

See [LsaOpenPolicy.yar](./LsaOpenPolicy.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
 - Non-standard processes (not lsass.exe or known management tools) calling `LsaOpenPolicy`
 - `LsaOpenPolicy` followed by LsaRetrievePrivateData or other sensitive LSA calls
 - Access requests asking for `POLICY_ALL_ACCESS` instead of minimal rights
 - Use of this API in tools running from unusual paths (temp folders, user profiles)
 - Correlation with privilege escalation or credential dumping behavior

## 🦠 Malware & Threat Actors Documented Abusing LsaOpenPolicy

### **Ransomware**
 - LockBit
 - Hive
 - Conti
 - AvosLocker

### **Commodity Loaders & RATs**
 - Emotet

### **APT & Threat Actor Toolkits**

### **Red Team & Open Source Tools**
 - MimiKatz


> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `LsaOpenPolicy`.

## 🧵 `LsaOpenPolicy` and Friends
`LsaOpenPolicy` is rarely the star of the show. It’s the opening act. Once that handle is open, it’s often followed by:

 - `LsaRetrievePrivateData` to extract stored secrets.
 - `LsaStorePrivateData` to implant persistence.
 - `LsaEnumerateTrustedDomains` to map trust paths.
 - `LsaAddAccountRights` or `LsaRemoveAccountRights` to quietly alter privileges.

Together, these calls turn a simple “open policy” operation into a major compromise pathway.

## 📚 Resources
- [Microsoft Docs: LsaOpenPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!