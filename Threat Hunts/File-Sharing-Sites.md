# File Sharing Sites

### Description

This Kusto looks for common file sharing services. This hunt will return a list of users that have visited one of the file sharing sites found in the IOC list. It will then enrich the user list with the User's information as well as the site they visited and the hostname they made the connection from.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 1d, set the timeframe of the investigation |
| ExcludedDomainNames | List any Domains that are on the IOC list but are common in your environment |

### Microsoft 365 Defender
```
let FileShareSites = externaldata (Tool:string,) [h@'https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/File%20Share%20Sites.csv']with (ignoreFirstRecord=flase, format='csv');
let Timeframe = ago(1d);
let ExcludedDomainNames = dynamic(["example.com"]);
DeviceNetworkEvents
| where Timestamp > Timeframe
| extend DomainName = extract(@"\w+\.\w+$",0,RemoteUrl)
| where DomainName != ""
| where DomainName in (FileShareSites)
| where not(DomainName in (ExcludedDomainNames))
| join  IdentityInfo on $left.InitiatingProcessAccountName == $right.AccountName
| summarize Total=count(),DomainName=make_set(DomainName),Devices=make_set(DeviceName),Department=max(Department),JobTitle=max(JobTitle),Email=max(EmailAddress) by AccountUpn
```

### MITRE ATT&CK Mapping
- Tactic: Exfiltration
- Technique ID: T1567.002
- [Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)

### References
https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/File%20Share%20Sites.csv

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/16/2024    | Initial publish                   |