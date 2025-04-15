<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/IT-DylanNguyen/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "test4dylan" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-14T23:33:32.3223106Z`. These events began at `2025-04-14T23:06:08.4768028Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "win10-mde-test-"  
| where InitiatingProcessAccountName == "test4dylan"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-04-14T23:06:08.4768028Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2025-04-14T23:11:27.9213303Z`, an employee on the "win10-mde-test-" device ran the file `tor-browser-windows-x86_64-portable-14.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "win10-mde-test-"  
| where ProcessCommandLine contains "tor-browser-windows"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "test4dylan" actually opened the TOR browser. There was evidence that they did open it at `2025-04-14T23:13:51.1896171Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "win10-mde-test-"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-14T23:16:25.2740942Z`, an employee on the "win10-mde-test-" device successfully established a connection to the remote IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "win10-mde-test-"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. Tor Download Initiated

- **Timestamp:** `2025-04-14 18:06:08 UTC`
- **Event:** The user "test4dylan" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\test4dylan\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Silent Installation Executed

- **Timestamp:** `2025-04-14 18:11:27 UTC`
- **Event:** The user "test4dylan" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\test4dylan\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Tor-Related Files Created

- **Timestamp:** `2025-04-14 18:11:43 UTC`
- **Event:** Multiple Tor-related files (e.g., `Tor.txt`, `Torbutton.txt`) were created on the user’s desktop.
- **Action:** File creation detected during unpacking of the portable browser.
- **File Path Example:** `C:\Users\test4dylan\Desktop\Tor.txt`

### 4. Tor Browser Opened

- **Timestamp:** `2025-04-14 18:13:51 UTC`
- **Event:** Execution of `firefox.exe` and `tor.exe` within the "Tor Browser" folder, showing the browser was launched.
- **Action:** Process execution detected.
- **File Path:** `C:\Users\test4dylan\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Network Activity via Tor Detected

- **Timestamp:** `2025-04-14 18:16:25 UTC`
- **Event:** A successful local connection was made from `firefox.exe` to `127.0.0.1:9150`, confirming use of the Tor network.
- **Action:** Network connection established to Tor’s SOCKS proxy port.
- **Process:** `firefox.exe`
- **File Path:** `C:\Users\test4dylan\Desktop\Tor Browser\Browser\firefox.exe`

### 6. File Created - TOR Shopping List

- **Timestamp:** `2025-04-14 18:33:32 UTC`
- **Event:** A file named `tor-shopping-list.txt` was created on the desktop, possibly indicating tracking or note-taking during TOR usage.
- **Action:** File creation detected.
- **File Path:** `C:\Users\test4dylan\Desktop\tor-shopping-list.txt`


---

## Summary

The user test4dylan downloaded and installed the Tor Browser silently, then launched it and successfully initiated Tor network communication via port 9150. The presence of a text file related to Tor further suggests intentional use. This activity may violate corporate policy and should be escalated for further review.

---

## Response Taken

TOR usage was confirmed on the endpoint `win10-mde-test-` by the user `test4dylan`. The device was isolated, and the user's direct manager was notified.

---
