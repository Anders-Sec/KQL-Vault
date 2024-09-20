# KQL Detections & Threat Hunting

[![Share on X](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text={text}&url={url}) [![Follow @anders0813](https://img.shields.io/twitter/follow/anders0813)](https://twitter.com/anders0813)
```
  ________            __ ______    __       _    __            ____ 
 /_  __/ /_  ___     / //_/ __ \  / /      | |  / /___ ___  __/ / /_
  / / / __ \/ _ \   / ,< / / / / / /       | | / / __ `/ / / / / __/
 / / / / / /  __/  / /| / /_/ / / /___     | |/ / /_/ / /_/ / / /_  
/_/ /_/ /_/\___/  /_/ |_\___\_\/_____/     |___/\__,_/\__,_/_/\__/  
                                                                    
                                                  
```
This repo is a collection of my most used KQL queries for both Threat Hunting as well as Detection Rules. 

# KQL Vault:
### Threat Hunting
| Name | Description | Source |
|------|-------------|--------|
| [Remote Access Tools](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/Remote-Access-Tools.md) |Looks for common remote access tools|Defender|
|[File Sharing Sites](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/File-Sharing-Sites.md)|Looks for common file sharing sites|Defender|
|[IOCs](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/IOC-Hunt.md)|Checks for IOCs across Defender tables|Defender|
|[DC Usage](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/DC-Usage-Hunt.md)|Shows DC usage metrics|Defender|
|[Emojis](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/Emoji-Hunt.md)|Looks for Emojis in Emails and Command Lines|Defender|
|[Duplicate MFA](https://github.com/Anders-Sec/KQL-Vault/blob/main/Threat%20Hunts/Duplicate-MFA-Hunt.md)|Looks for duplicate SMS numbers being registered by multiple users|Sentinel|

### Detection Rules
| Name | Description | Source |
|------|-------------|--------|
| [Specula C2](https://github.com/Anders-Sec/KQL-Vault/blob/main/Detection%20Rules/Specula-C2-Detection.md) | Detection of the TrustedSec Specula C2 Framework | Defender|
| [Defender Exclusion Modification](https://github.com/Anders-Sec/KQL-Vault/blob/main/Detection%20Rules/Defender-Exclusion-Modification.md) | Detection of Defender For Endpoint Exclusion Modification |Defender|
| [Suspicious Bulk File Modification](https://github.com/Anders-Sec/KQL-Vault/blob/main/Detection%20Rules/Bulk-File-Modification.md)  | Detection for Bulk file renaming in a set time window | Defender |

---
> [!WARNING]  
> The KQL Queries in this repository are provided as a general reference for creating Detection Rules. Every environment is unique and will require tuning by the user before implementing these rules into production. It is up to the user to fully understand and test these KQL Queries before implementing them into their environments.
