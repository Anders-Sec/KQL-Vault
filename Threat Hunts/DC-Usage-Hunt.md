# Domain Controller Usage Hunt

### Description

This Kusto looks at query , logon and directory events on all domain controllers. This can help identify any hot spots in your domain infrastructure. Ideally every device will split the load evenly but this is next to impossible in larger environments. The data is showed as either a table breaking down each category or a Pie chart showing to combined percentage. 


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Domain     |  Set this to your primary domain |
|    Timeframe     |  Default: 7d, sets the timeframe of the investigation |

### Microsoft 365 Defender
```
let Domain = "example.com";
let Timeframe = ago(7d);
let directoryEvents = IdentityDirectoryEvents 
| where Timestamp >= Timeframe
| where not(isempty(DestinationDeviceName))
| where DestinationDeviceName endswith Domain
| summarize Total=count() by DestinationDeviceName;
let logonEvents = IdentityLogonEvents
| where Timestamp >= Timeframe
| where not(isempty(DestinationDeviceName))
| where DestinationDeviceName endswith Domain
| summarize Total=count() by DestinationDeviceName;
let queryEvents = IdentityQueryEvents
| where Timestamp >= Timeframe
| where not(isempty(DestinationDeviceName))
| where DestinationDeviceName endswith Domain
| summarize Total=count() by DestinationDeviceName;
directoryEvents
| join logonEvents on DestinationDeviceName
| join queryEvents on DestinationDeviceName
| project DestinationDeviceName, directoryEvents=Total, logonEvents=Total1, queryEvents = Total2
| extend DirectoryEventsPercentage = round(100.0 * directoryEvents / toscalar(directoryEvents | summarize sum(Total)), 2)
| extend LogonEventsPercentage = round(100.0 * logonEvents / toscalar(logonEvents | summarize sum(Total)), 2)
| extend QueryEventsPercentage = round(100.0 * queryEvents / toscalar(queryEvents | summarize sum(Total)), 2)
| extend Combined = round((DirectoryEventsPercentage+LogonEventsPercentage+QueryEventsPercentage)/3,2)
| project DestinationDeviceName,QueryEventsPercentage,LogonEventsPercentage,DirectoryEventsPercentage,Combined
//
//Uncomment the below 3 lines to show the data as a Pie Chart
//| extend DeviceName = iff(Combined > 3,DestinationDeviceName,"Other")
//| summarize Percent = sum(Combined) by DeviceName
//| render piechart
```

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/20/2024    | Initial publish                   |