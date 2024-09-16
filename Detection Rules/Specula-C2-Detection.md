# Specula C2

### Description

This detection alerts on the modification of Outlook registry keys associated with the TrustedSec Specula C2 Framework.


### Recommended Rule Settings
| Severity    | Frequency      | Action      |
| ----------- |--------------- |-------------|
|    High     |  Continuous (NRT) |   Initiate investigation   |

### Microsoft 365 Defender
```
DeviceRegistryEvents
| where RegistryKey matches regex @"\\SOFTWARE\\Microsoft\\Office\\.+\\Outlook\\Webview\\"
```

### MITRE ATT&CK Mapping
- Tactic: Command and Control
- Technique ID: T1071.001
- [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

### References
https://trustedsec.com/resources/tools/specula

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/16/2024    | Initial publish                   |