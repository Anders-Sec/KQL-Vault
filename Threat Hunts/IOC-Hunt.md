# IOC Hunt

### Description

This Kusto pulls down a csv of IOCs and queries various places in Defender to look for hits. The URL can be changed to your own IOC file and can be used in an alarm to verify specific IOCs are not found in your environment.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 7d, sets the timeframe of the investigation |

### Microsoft 365 Defender
```
let Timeframe = ago(7d);
let IOCRaw = externaldata (WindowsRegistryKey:string,AutonomousSystem:string,MACAddress:string,ssdeep:string,URL:string,IPv6:string,Directory:string,IP:string,MD5:string,SHA384:string,Email:string,SHA1:string,FilePath:string,SHA256:string,IPv4CIDR:string,SHA512:string,Domain:string,SHA224:string) [h@'https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/Sample-Blocked-indicators.csv']with (ignoreFirstRecord=true, format='csv')
| summarize WindowsRegistryKey = make_set(WindowsRegistryKey),AutonomousSystem = make_set(AutonomousSystem),MACAddress = make_set(MACAddress),ssdeep = make_set(ssdeep),URL = make_set(replace_string(replace_string(replace_string(URL,"hxxp","http"),"[",""),"]","")),IPv6 = make_set(IPv6),Directory = make_set(Directory),IP = make_set(replace_string(replace_string(IP,"[",""),"]","")),MD5 = make_set(MD5),SHA384 = make_set(SHA384),Email = make_set(replace_string(replace_string(Email,"[",""),"]","")),SHA1 = make_set(SHA1),FilePath = make_set(FilePath),SHA256 = make_set(SHA256),IPv4CIDR = make_set(IPv4CIDR),SHA512 = make_set(SHA512),Domain = make_set(replace_string(replace_string(Domain,"[",""),"]","")),SHA224 = make_set(SHA224)
| extend bag = bag_pack("WindowsRegistryKey",WindowsRegistryKey,"AutonomousSystem",AutonomousSystem,"MACAddress",MACAddress,"ssdeep",ssdeep,"URL",URL,"IPv6",IPv6,"Directory",Directory,"IP",IP,"MD5",MD5,"SHA384",SHA384,"Email",Email,"SHA1",SHA1,"FilePath",FilePath,"SHA256",SHA256,"IPv4CIDR",IPv4CIDR,"SHA512",SHA512,"Domain",Domain,"SHA224",SHA224)
| project bag;
let IOC = dynamic_to_json(toscalar(IOCRaw));
let HashResults = DeviceProcessEvents
| where Timestamp > Timeframe
| where (SHA1 in (parse_json(IOC)["SHA1"]) and SHA1 != "") or (SHA256 in (parse_json(IOC)["SHA256"]) and SHA256 != "") or (MD5 in (parse_json(IOC)["MD5"]) and MD5 != "") or (InitiatingProcessSHA1  in (parse_json(IOC)["SHA1"]) and InitiatingProcessSHA1 != "") or (InitiatingProcessSHA256 in (parse_json(IOC)["SHA256"]) and InitiatingProcessSHA256 != "") or (InitiatingProcessMD5 in (parse_json(IOC)["MD5"]) and InitiatingProcessMD5 != "")
| extend Category = "Hash";
let NetworkResults = DeviceNetworkEvents
| where Timestamp > Timeframe
| where (RemoteIP in (parse_json(IOC)["IP"]) and RemoteIP != "") or (LocalIP in (parse_json(IOC)["IP"]) and LocalIP != "") or (RemoteIP in (parse_json(IOC)["IPv6"]) and RemoteIP != "") or (LocalIP in (parse_json(IOC)["IPv6"]) and LocalIP != "") or (RemoteUrl in (parse_json(IOC)["URL"]) and RemoteUrl != "") //(extract( @"(?:https?\:\/\/)?([\w\.]+)",1,RemoteUrl) in (parse_json(IOC)["Domain"]) and RemoteUrl != "") or {Searching for Domains in URLs is really slow, still working out a better solution}
| extend Category = "Network";
let RegistryResults = DeviceRegistryEvents
| where Timestamp > Timeframe
| where RegistryKey in (parse_json(IOC)["RegistryKey"]) and RegistryKey != ""
| extend Category = "Registry";
let EmailResults = EmailEvents
| where Timestamp > Timeframe
| where (SenderMailFromAddress in (parse_json(IOC)["Email"]) and SenderMailFromAddress != "") or (SenderFromAddress in (parse_json(IOC)["Email"]) and SenderFromAddress != "") or (SenderDisplayName in (parse_json(IOC)["Email"]) and SenderDisplayName != "") or (SenderFromDomain  in (parse_json(IOC)["Domain"]) and SenderFromDomain != "") or (RecipientEmailAddress  in (parse_json(IOC)["Email"]) and RecipientEmailAddress != "") or (SenderIPv4 in (parse_json(IOC)["IP"]) and SenderIPv4 != "") or (SenderIPv6 in (parse_json(IOC)["IPv6"]) and SenderIPv6 != "")
| extend Category = "Email";
union EmailResults,HashResults,RegistryResults,NetworkResults
```

### References
https://raw.githubusercontent.com/Anders-Sec/KQL-Vault/refs/heads/main/IOCs/Sample-Blocked-indicators.csv

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/20/2024    | Initial publish                   |