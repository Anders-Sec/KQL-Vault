# Remote Access Tools

### Description

This Kusto looks for common remote access tools being used on endpoints. The Kusto will return a list of users who have used one of the Files from the IOCs list. It will enrich this list with the user's information as well as the hostnames where the use used those files.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 7d, sets the timeframe of the investigation |
| ExcludedFileNames | A list of filenames names excluded from the hunt. Used if one of the products in the IOC feed is used in your environment| 

### Microsoft 365 Defender
```
let RemoteAccessFileNames = externaldata (Tool:string,) [h@'https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/Remote%20Access%20IOC.csv']with (ignoreFirstRecord=flase, format='csv');
let Timeframe = ago(7d);
let ExcludedFileNames = dynamic(["example.exe"]);
DeviceProcessEvents
| where Timestamp > Timeframe
| where FileName in~ (RemoteAccessFileNames)
| where not(FileName in~ (ExcludedFileNames))
| join  IdentityInfo on AccountUpn
| summarize Total=count(),Filename=make_set(FileName),Devices=make_set(DeviceName),Department=max(Department),JobTitle=max(JobTitle),Email=max(EmailAddress),Hash = make_set(SHA256) by AccountUpn

```

### MITRE ATT&CK Mapping
- Tactic: Command and Control
- Technique ID: T1219
- [Remote Access Software](https://attack.mitre.org/techniques/T1219/)

### References
https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/Remote%20Access%20IOC.csv

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/16/2024    | Initial publish                   |