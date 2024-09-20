# Duplicate MFA Hunt

### Description

This Kusto looks for multiple users with the same MFA phone number being registered. This can be an indication that a threat actor gained access to the accounts and linked their SMS number as a form of persistence. Ideally every user has their own unique phone MFA but often times threat actor will reuse phone numbers.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 30d, sets the timeframe of the investigation |

### Microsoft Sentinel
```
let Timeframe = ago(30d);
AuditLogs
| where TimeGenerated >= Timeframe
| where OperationName == "Update user" and TargetResources contains "StrongAuthenticationMethod"
| extend Target = tostring(TargetResources[0].userPrincipalName)
| where TargetResources contains "PhoneNumber"
| extend PhoneNumber = tostring(parse_json(tostring(TargetResources[0].modifiedProperties[1].newValue))[0].PhoneNumber)
| where PhoneNumber != ""
| project Target,PhoneNumber
| summarize Users = make_set(Target) by PhoneNumber
| extend UserCount = array_length(Users)
| where UserCount > 1
```

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/20/2024    | Initial publish                   |