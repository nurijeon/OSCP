## Windows Process Analysis
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
