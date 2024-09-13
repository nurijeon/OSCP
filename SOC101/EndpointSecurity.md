## Endpoint Security controls
Org assess which controls align to their specific threat model and environment and prioritize the implementation based on that relevance along with available tools.
**Antivirus**
- Scan files and activities
- Matching patterns and signatures

**Endpoint Detection and Response(EDR)**
- Real-time monitoring and response
- Agent required
- Monitor process, file, registry and network activity

**Extended Detection and Response (XDR)**
- Integration of multiple security controls and telemetry
- Runbooks and automamted response to routine threats

**DLP**
- Protect sensitive data at rest, transit and in processing
- Access control, data masking

**User and Entity Behavior Analytics(UBA)**
- Monitoring user behavior patterns
- Detect deviations from historic and contextual baseline
- Insider threats, account compromise, data exfiltration   

**HIDS/HIPS**
- Host-based Intrusion Detection System(HIDS)

## Windows Network Analysis
**new view: Displays a list of resources being shared on a specified host**
```bash
new view \\127.0.0.1
```

**net share**
```bash
mkdir exfil
net share Exfil=C:\Users\njeon\Documents\exfil

# check resources shared on our local system
net share
```

**net session: Display all inbound session**
```bash
net session
```

**net use: connect/disconnect computer from a shared resources**
```bash
net use X: \\127.0.0.1\Exfil

# information on mapped connections
net use
```

**netstat**
```bash
# -a: Displays all active coonnections and which TCP and UDP ports are listening for a connection
# -n: Do not resolve dns names
# -o: Include PID
# -b: Display the file name
```

**tcpview**



## Windows Process Analysis
**Windows core processes**
- System(Windows) processes
- User processes


**Process**
```bash
tasklist

# for more vorbose information
tasklist /V

# filter process by pid
tasklist /FI "PID eq 2222"

# filter process by imagename
tasklist /FI "IMAGENAME eq program.exe"

# filter process by pid and get associated dll
tasklist /FI "PID eq 2222" /M
```


**WMIC** Gather more information
```bash
# retrieve name and parent process id
wmic process where processid=2088 get name, parentprocessid, processid

wmic process get name, parentprocessid, processid | find "192"

# get the commandline used
wmic process where processid=2088 get commandline
```

## Windows Core Processes
**System Process**
- No path
- PID 4
![image](https://github.com/user-attachments/assets/4b99fe1f-397d-44da-8c3f-28627ab897fa)

**smss.exe Process**
- Windows Session Manager
- Initiating and managing user sessions
- Launches child processes - wininit.exe csrss.exe
- ![image](https://github.com/user-attachments/assets/1becaedc-2a48-4a41-b772-39d2f78de894)


**csrss.exe**
