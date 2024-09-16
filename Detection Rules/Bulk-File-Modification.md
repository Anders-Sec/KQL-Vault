# Suspicious Bulk File modification

### Description

This rule looks for bulk file name modification in a short time window. This activity is consistent with ransomware actors when they encrypt files and modify the file extension.


### Recommended Rule Settings
| Severity    | Frequency      | Action      |
| ----------- |--------------- |-------------|
|    High     |  Every Hour |   Initiate investigation   |

### Microsoft 365 Defender
```
let Threshold = 300; //Value is unique to each environment. Play around with the value to see what works best for you.
DeviceFileEvents
| where not( ActionType in ("FileCreated","FileDeleted"))
| where PreviousFileName != ""
| where FileName != PreviousFileName
| where FileName matches regex @"\."
| summarize DeviceId = max(DeviceId),ReportId = max(ReportId),AccountName = max(InitiatingProcessAccountName), Points=countif(extract(@"(.+)\.\w+$",1,FileName) == extract(@"(.+)\.\w+$",1,PreviousFileName)) by bin(Timestamp, 5m), DeviceName
| where Points >= Threshold
```

### MITRE ATT&CK Mapping
- Tactic: Impact
- Technique ID: T1486
- [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)


### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/16/2024    | Initial publish                   |