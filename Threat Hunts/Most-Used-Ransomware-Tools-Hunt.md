# Most Used Ransomware Tools

### Description

This Kusto combines detections for the top 10 known Ransomware Tools. This can be used as a starting point to hunt down malicious uses of common tools used in ransomware campaigns and convert this Kusto into a detection rule based on your environment.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 30d, sets the timeframe of the investigation |

### Microsoft 365 Defender
```
let Timeframe = ago(30d);
//netscan.exe Detection
let netscan = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName == "netscan.exe" or 
        ProcessVersionInfoFileDescription == "Application for scanning networks" or 
        ProcessVersionInfoProductName == "Network Scanner"
| project DetectionName="netscan",Timestamp,DeviceName,AccountUpn;
//advanced_ip_scanner.exe Detection
let AIS = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains "advanced_ip_scanner" or
        ProcessVersionInfoFileDescription == "Advanced IP Scanner" or
        ProcessVersionInfoProductName == "Advanced IP Scanner"
| project DetectionName="advanced_ip_scanner",Timestamp,DeviceName,AccountUpn;
//adfind Detection
let adfind = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains "adfind" or
        ProcessCommandLine contains "-gcb -sc trustdmp" or
        ProcessCommandLine contains '-f "(objectcategory=group)"' or
        ProcessCommandLine contains "-f (objectcategory=group)" or
        ProcessCommandLine contains "-subnets -f (objectCategory=subnet)" or
        ProcessCommandLine contains '-f "(objectcategory=organizationalUnit)"' or
        ProcessCommandLine contains "-f (objectcategory=organizationalUnit)" or
        ProcessCommandLine contains '-f "objectcategory=computer"' or
        ProcessCommandLine contains '-f "(objectcategory=person)"' or
        ProcessCommandLine contains "-f (objectcategory=person)"
| project DetectionName="adfind",Timestamp,DeviceName,AccountUpn;
//GMER
let GMER = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName == "gmer.exe" or
        SHA1 == "539C228B6B332F5AA523E5CE358C16647D8BBE57" or
        SHA1 == "539c228b6b332f5aa523e5ce358c16647d8bbe57"
| project DetectionName="GMER",Timestamp,DeviceName,AccountUpn;
//Cobalt Strike Detection WIP
//Mimikatz Detection
let mimi = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains 'mimikatz' or
        ProcessCommandLine contains 'dpapi::masterkey' or
        ProcessCommandLine contains 'eo.oe.kiwi' or
        ProcessCommandLine contains 'event::clear' or
        ProcessCommandLine contains 'event::drop' or
        ProcessCommandLine contains 'gentilkiwi.com' or
        ProcessCommandLine contains 'kerberos::golden' or
        ProcessCommandLine contains 'kerberos::ptc' or
        ProcessCommandLine contains 'kerberos::ptt' or
        ProcessCommandLine contains 'kerberos::tgt' or
        ProcessCommandLine contains 'Kiwi Legit Printer' or
        ProcessCommandLine contains 'lsadump::' or
        ProcessCommandLine contains 'mimidrv.sys' or
        ProcessCommandLine contains @'\mimilib.dll' or
        ProcessCommandLine contains 'misc::printnightmare' or
        ProcessCommandLine contains 'misc::shadowcopies' or
        ProcessCommandLine contains 'misc::skeleton' or
        ProcessCommandLine contains 'privilege::backup' or
        ProcessCommandLine contains 'privilege::debug' or 
        ProcessCommandLine contains 'privilege::driver' or
        ProcessCommandLine contains 'sekurlsa::'
| project DetectionName="Mimikatz",Timestamp,DeviceName,AccountUpn;
//AnyDesk Detection
let AnyDesk_Process = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains 'anydesk'
| project DetectionName="AnyDesk",Timestamp,DeviceName,AccountUpn;
let AnyDesk_Network = DeviceNetworkEvents
| where Timestamp > Timeframe
| where RemoteUrl contains "anydesk.com"
| project DetectionName="AnyDesk",Timestamp,DeviceName,AccountUpn=InitiatingProcessAccountUpn;
//Atera Detection
let Atera = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains "AteraAgent"
| project DetectionName="Atera",Timestamp,DeviceName,AccountUpn;
//SplashTop Detection
let SplashTop_Process = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName contains "SplashTop" or
        ProcessVersionInfoFileDescription contains "SplashTop" or 
        ProcessVersionInfoProductName contains "SplashTop"
| project DetectionName="SplashTop",Timestamp,DeviceName,AccountUpn;
let SplashTop_Network = DeviceNetworkEvents
| where Timestamp > Timeframe
| where RemoteUrl contains "SplashTop"
| project DetectionName="SplashTop",Timestamp,DeviceName,AccountUpn=InitiatingProcessAccountUpn;
//PsExec Detection
let PsExec = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName =~ "psexec.exe"
| project DetectionName="PsExec",Timestamp,DeviceName,AccountUpn;
//Rclone Detection
let Rclone = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName == 'rclone.exe'
| project DetectionName="Rclone",Timestamp,DeviceName,AccountUpn;
//Mega Detection
let Mega_Process = DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName == 'megasync.exe'
| project DetectionName="Mega",Timestamp,DeviceName,AccountUpn;
let Mega_Network = DeviceNetworkEvents
| where Timestamp > Timeframe
| where RemoteUrl contains "mega.nz"
| project DetectionName="Mega",Timestamp,DeviceName,AccountUpn=InitiatingProcessAccountUpn;
union netscan,AIS,adfind,GMER,mimi,AnyDesk_Network,AnyDesk_Process,Atera,SplashTop_Network,SplashTop_Process,PsExec,Rclone,Mega_Network,Mega_Process

```

### MITRE ATT&CK Mapping
- Tactic: Network Service Discovery
- Technique ID: T1046
- [Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

- Tactic: Remote System Discovery
- Technique ID: T1018
- [Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

- Tactic: Impair Defenses: Disable or Modify Tools
- Technique ID: T1562.001
- [Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

- Tactic: Exfiltration Over Web Service: Exfiltration to Cloud Storage
- Technique ID: T1567.002
- [Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)

- Tactic: Command and Control
- Technique ID: T1219
- [Remote Access Software](https://attack.mitre.org/techniques/T1219/)



### References
https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/Tools/MostUsedTools.md

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 11/1/2024    | Initial publish                   |