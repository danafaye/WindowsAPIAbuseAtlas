# NetLocalGroupGetMembers

## 🚀 Executive Summary
**`NetLocalGroupGetMembers`** enumerates local group memberships over the network. Attackers use it to find admin accounts, map lateral movement paths, and uncover misconfigurations. It’s essential for post-exploitation recon—exposing group relationships across domains for privilege escalation and persistence. Legit admins use it too, but threat actors love it for its visibility into who’s really in control.

## 🚩 Why It Matters
`NetLocalGroupGetMembers` reveals local group memberships, essential for managing permissions but also a favorite tool for attackers. By quietly enumerating group members, hackers identify high-value targets like admins and privileged users. This info helps them plan privilege escalation and lateral movement early in an attack. Understanding its abuse is key to spotting and stopping stealthy reconnaissance.

## 🧬 How Attackers Abuse It

 - **Privilege Discovery**: Attackers use this API to find admin group members and spot high-value accounts — the prime targets for takeover.

 - **Reconnaissance Operations**: It’s a favorite for quietly mapping out who’s who and figuring out paths for moving laterally across a network.

 - **Post-Exploitation Activities**: Once inside, hackers validate what a compromised account can do, hunt for more targets, and sniff out service accounts running security tools to stay under the radar.

## 🛡️ Detection Opportunities

- **What to watch for**: Rapid-fire group queries targeting admin or multiple groups in quick succession, especially from unusual accounts or systems. Cross-domain group enumeration is a red flag, too. Keep in mind, attackers often use higher-level tools like PowerShell or PowerView that call `NetLocalGroupGetMembers` indirectly, so direct API calls might be rare or hidden.

- **What to capture**: Record source accounts and systems, targeted groups, query frequency and volume, plus network context. Deep API or syscall monitoring can catch stealthier indirect usage, so combine these logs with telemetry from native tools and command-line activity for fuller visibility.


## 🦠 Malware & Threat Actors Documented Abusing NtMapViewOfSection

**NetLocalGroupGetMembers** rarely appears explicitly in threat reports because attackers usually access it indirectly through PowerShell (`Get-LocalGroupMember`), built-in commands (`net localgroup`), or frameworks like PowerView. These tools call the API under the hood, hiding direct usage. Detecting `NetLocalGroupGetMembers` requires deep API or syscall monitoring beyond typical telemetry.

### Read Team & Open Source Tools
 - PowerView
 - SharpView
 - PowerSploit recon

### 🧵 NetLocalGroupGetMembers and Friends
These Net* APIs are a goldmine for recon. `NetLocalGroupEnum` lets attackers list all the local groups on a system, while `NetUserEnum` spills the names of all user accounts. From there, `NetUserGetLocalGroups` maps users to their local group memberships, and `NetGroupGetUsers` does the same for domain groups. Used together, they give attackers a full picture of group structures and relationships — a perfect setup for privilege mapping, lateral movement, or just figuring out who’s worth targeting next.

## References

- [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupgetmembers)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)