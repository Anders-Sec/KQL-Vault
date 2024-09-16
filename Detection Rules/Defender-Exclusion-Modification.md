# Defender Exclusion Modification

### Description

This detection looks for changes in the registry keys where Defender for Endpoint stores it's exclusions. 


### Recommended Rule Settings
| Severity    | Frequency      | Action      |
| ----------- |--------------- |-------------|
|    Medium     |  Continuous (NRT) |   Initiate investigation   |

### Microsoft 365 Defender
```
let RegistryKeys = dynamic([@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"]);
let DeviceExclusions = dynamic(["Device1","Device2"]);
DeviceRegistryEvents
| where RegistryKey in (RegistryKeys)
| where not(DeviceName in (DeviceExclusions))
```

### MITRE ATT&CK Mapping
- Tactic: Defense Evasion
- Technique ID: T1562.001
- [Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/16/2024    | Initial publish                   |