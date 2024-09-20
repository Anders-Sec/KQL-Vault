# Emoji Hunt

### Description

This Kusto looks for Emoji ascii characters in both Email Subjects lines and Device process Command Lines. The results can be very noisy but can provide useful info that be be further used to hunt down malicious email campaigns or commands used in malware.


### Hunting Parameters
| Name    | Description      |
| ----------- |--------------- |
|    Timeframe     |  Default: 7d, sets the timeframe of the investigation |

### Microsoft 365 Defender (Email)
```
let Timeframe = ago(7d);
EmailEvents
| where Timestamp > Timeframe
| where DeliveryAction in ("Delivered","Junked")
| extend Chars = extract_all(@"([\u{FF0D}-\u{1FAF9}]+)",Subject)
| where not(isnull(Chars))
| summarize Timestamp = max(Timestamp), Subject = make_set(Subject), Chars = make_set(Chars), NetworkMessageId = make_set(NetworkMessageId) by SenderFromAddress
```
### Microsoft 365 Defender (DeviceProcessEvents)
```
let Timeframe = ago(7d);
DeviceProcessEvents
| where Timestamp > Timeframe
| where ProcessCommandLine matches regex @"([\u{FF0D}-\u{1FAF9}]+)"
```

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 9/20/2024    | Initial publish                   |