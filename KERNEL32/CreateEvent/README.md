# 🔔 CreateEvent

## 🚀 Executive Summary
If Windows had a calendar, `CreateEvent` would be the one setting all the reminders. It’s not scheduling your dentist appointment though. It’s setting little flags in memory so processes and threads can coordinate like, “Hey buddy, I’m done, your turn.” Pretty harmless at face value. But as usual, attackers show up and use it for some seriously shady reasons. And yes… sometimes they even name their events, leaving little breadcrumbs for analysts to find.

## 🔍 What is CreateEvent?
At its core, `CreateEvent` is Windows’ way of letting programs raise their hand and say, “I’m finished with my thing, go ahead and do yours.” It creates a synchronization object called an event. Think of it as a neon “OPEN” sign that flips on and off to coordinate threads. Normally, this is totally boring and helps programs avoid stepping all over each other. But sometimes malware likes to put its own name on that neon sign.

## 🚩 Why It Matters
Any time you give attackers something to “signal” or “wait” on, they can twist it into something useful for themselves. Named events? Even better. Malicious code can leave fun little Easter eggs in memory like `Global\\SuperSecretRansomwareSwitch` mostly to enforce single-instance execution, prevent multiple copies of itself from running, or even detect sandboxed or analysis environments. It’s subtle, but it works.

## 🧬 How Attackers Abuse It
Malware often uses `CreateEvent` as a cheap way to make sure only one copy of itself runs at a time. Picture a ransomware binary spawning, checking for an event, and if it already exists, it says, “Oh, my evil twin is already here. I’ll just bail.”

Beyond single instance enforcement, `CreateEvent` can also play a role in anti-analysis. Malware can check for leftover named events from previous runs or sandbox artifacts and decide not to execute its payload if it suspects it’s being watched. Threads may park on events indefinitely, making analysts think the process is idle while the malware quietly detects or waits out the environment.

Occasionally, malware uses events to coordinate multiple components, but documented evidence of this is rare. Named events are primarily used for status signaling or enforcing execution constraints rather than full-blown interprocess communication.

💡 Quick note: `CreateEvent` itself doesn’t watch or detect anything. If malware or not malware wants to respond to something like a new RDP session, the event is just a placeholder or signal. You’d still need actual monitoring logic (like WTS APIs or Event Log subscriptions) to flip the switch. `CreateEvent` just makes the doorbell; it doesn’t ring it for you.

## 🛡️ Detection Opportunities
Spotting `CreateEvent` in isolation is like seeing someone buy duct tape. Not inherently bad, but context matters. Look for suspicious event names (especially the ones that scream “malware dev left this here”), repeated creation attempts across weird processes, or events tied directly to persistence, single instance enforcement, or anti-analysis routines.

Here are some sample YARA rules to detect suspicious use of `CreateEvent`:

See [CreateEvent.yar](./CreateEvent.yar).

> **Note:** Use these YARA rules at your own risk. They are loosely scoped and intended primarily for threat hunting and research purposes; **NOT** for deployment in detection systems that require a low false positive rate. Please review and test in your environment before use.

### 🐾 Behavioral Indicators
If you see events with names like `Global\\ransom_is_here` or `Local\\malware_mutex`, it’s not exactly the subtle kind of evil. You’ll also find malware setting events and then waiting forever on them ... like it’s stuck in line at the DMV. Those dead giveaways can be gold for detection.

> 💡 Pro tip: If you’re curious about what events a process is juggling, crack open Process Explorer. Right click the process, hit Properties, and head over to the Handles tab. Filter for “Event” and you’ll see all the named events it’s holding onto. Some will look boring and system-ie, others might scream “malware dev left this here.” Just remember: not every event has to have a name. If it’s only meant for the process that created it, Windows doesn’t bother slapping a label on it. Named events are only really needed when other processes need to join the party.

Some more things worth keeping an eye on:

 - **Weirdly named events or event names tied to payloads**: Anything that looks like `Global\\RansomwareName`, `Local\\1337h4x0r`, or random gibberish like `asdf1234qwer` doesn’t scream “Windows internals.” Legit event names tend to look corporate boring, but of course bad guys can name their stuff borning names too.
 - **Suspicious scope**: Global events can be touched by any session, which is perfect for malware that wants persistence across users. If a random unsigned binary is spinning up `Global\\` events, that’s eyebrow raising.
 - **Single instance enforcement**: Malware often creates an event at startup and bails if it already exists. You’ll see a quick "create then check pattern", like “Am I already here? Yes? Okay, shutting down.” Normal apps don’t usually care that much.
 - **Interprocess communication shenanigans**: Events used to signal between totally unrelated processes (like notepad.exe setting a flag for wscript.exe) should set off your spidey sense.
 - **Long, weird waits**: Malware sometimes waits on an event forever. Essentially parking until some other evil component flips the switch. If you see a thread camping out on `WaitForSingleObject` for hours, that’s sketchy.
 - **Excessive event churn**: Rapid creation and destruction of events in a short time frame can look like malware testing its environment or synchronizing multiple payloads.
 - **Cross-architecture oddities**: 32 bit processes creating events that 64 bit processes immediately check is often a loader-to-payload handoff trick.
 - **Persistence tricks**: Some malware will abuse events to coordinate with autostarted processes, using them as poor man’s IPC instead of proper Windows services or registry keys.

Legit software uses `CreateEvent` all the time, but the patterns, names, and context give malware away. It’s not about the API. Like alwayas ... it’s about the context.

## 🦠 Malware & Threat Actors Documented Abusing CreateEvent

### **Ransomware**
 - Albabat 
 - BlackByte

### **Commodity Loaders & RATs**
 - Amatera Stealer
 - QakBot
 - ThemeForestRAT

### **APT & Threat Actor Toolkits**
 - APT19
 - Lazarus

### **Red Team & Open Source Tools**
 - Metasploit
 - Atomic Red Team 

> **Note:** This list isn’t exhaustive. It is possible more modern malware families and offensive security tools use `CreateEvent`.

## 🧵 `CreateEvent` and Friends
If `CreateEvent` is the party starter, then its close cousins `OpenEvent`, `SetEvent`, and `ResetEvent` are the crew that keeps the lights flashing. Together, they form the synchronization gang that malware leans on to run smoothly while evading your defenses.

## 📚 Resources
- [Microsoft Docs: CreateEvent](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
- [Windows API Abuse Atlas](https://github.com/danafaye/WindowsAPIAbuseAtlas)

> Open a PR or issue to help keep this list up to date!