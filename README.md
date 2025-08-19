# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/maggiemachuca/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` table for ANY file that had the string `tor` in it and discovered what looks like the user “krispy” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-16T03:52:18.6062319Z`. These events began at: `2025-08-16T03:25:17.6245288Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "krisp-machine-3"
| where InitiatingProcessAccountName == "krispy"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-16T03:25:17.6245288Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1466" height="536" alt="image" src="https://github.com/user-attachments/assets/a730e07f-68af-4e15-b8e9-3b580700e866" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any ProcessCommandLine that contained the string `tor-browser-windows-x86_64-portable-14.5.5.exe`. Based on the logs returned, at `2025-08-16T03:31:29.1616741Z`, an employee “krispy” on the machine named “krisp-machine-3” launched the Tor Browser portable installer (version 14.5.5) from their Downloads folder silently, with no additional command-line options. The executable’s fingerprint is `SHA-256: 6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d`

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "krisp-machine-3"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1493" height="175" alt="image" src="https://github.com/user-attachments/assets/9f55aee9-a9db-47d2-8929-0cfe4da39462" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user “krispy” actually opened the tor browser. There was evidence that they did open it at `2025-08-16T03:31:58.7071151Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "krisp-machine-3"
| where FileName has_any ("tor-browser.exe", "tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1464" height="484" alt="image" src="https://github.com/user-attachments/assets/ebf23782-7236-4a95-99ad-825de1efe7f2" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

At `2025-08-16T03:54:12.5339919Z` on the computer named “krisp-machine-3,” the user “krispy” successfully established a network connection. The process that initiated it was `tor.exe`, located in `c:\users\krispy\desktop\tor browser\browser\torbrowser\tor\tor.exe`. It connected to the remote IP address `82.165.21.136` on port `9001`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "krisp-machine-3"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1400" height="487" alt="image" src="https://github.com/user-attachments/assets/0f6e4e5f-4364-49b7-993c-e4cd0377c225" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-16T03:25:17.6245288Z`
- **Event:** Tor-related files begin appearing on the device—indicative of downloads or staging of Tor components by user “krispy.”
- **Action:**  Initial file creation or modification detected in the Desktop or Downloads folder.
- **File Path:** C:\Users\krispy\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-16T03:31:29.1616741Z`
- **Event:**  User “krispy” launches the portable Tor Browser installer (version 14.5.5) from the Downloads folder. It begins execution without any additional command-line flags.
- **Action:**  Process execution of Tor Browser installer detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\krispy\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-16T03:31:58.7071151Z`
- **Event:** Tor Browser processes (e.g., `tor-browser.exe`, `tor.exe`, `firefox.exe`) launch—indicating the browser is actively running.
- **Action:** Process creation of Tor browser-related executables detected.
- **File Path:** `Paths correspond to the installed Tor Browser directory, likely on the Desktop under “`tor browser\browser\torbrowser\tor…`”`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-16T03:54:12.5339919Z`
- **Event:**  `tor.exe` (located in the Tor Browser folder on the Desktop) successfully establishes a network connection to remote IP `82.165.21.136` via port `9001`, with additional connections over port `443`.
- **Action:** Network connection success by Tor executable.
- **File Path:** `C:\Users\krispy\Desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-16T03:52:18.6062319Z`
- **Event:** A text file named “`tor-shopping-list.txt`” appears on the Desktop.
- **Action:** File creation detected.
- **File Path** `C:\Users\krispy\Desktop\tor-shopping-list.txt`


---

## Summary

The user “krispy” on the “krisp-machine-3” device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the “shopping list” file.


---

## Response Taken

TOR usage was confirmed on endpoint `krisp-machine-3` by the user `krispy`. The device was isolated and the user's direct manager was notified.

---
