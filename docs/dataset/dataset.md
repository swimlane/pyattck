# External Datasets

This page outlines and provides detailed information regarding the data generated and used with the `pyattck` python package.

## Data Categories

At this time, a shareable JSON file is generated on a daily basis and pushed to the `pyattck` repository.  You can view this raw file here: [generated_attck_data.json](https://raw.githubusercontent.com/swimlane/pyattck/master/generated_attck_data.json)

This generated JSON file has the following main keys:

- timestamp
- techniques
    - technique_id
    - commands
    - parsed_datasets
    - command_list
    - attack_paths
    - queries
    - possible_detections
- actors
    - israel
    - iran
    - middle_east
    - north_korea
    - china
    - unknown
    - other
    - nato
    - russia
    - _Each actor will contain a list of dictionaries also called 'actors'.  Each dictionary will have the following keys:_
        - actor_names
        - target
        - operations
        - description
        - tools
        - links
        - attck_id
        - comment
- tools
    - names
    - links
    - family
    - comments
- c2_data
    - name_of_c2
        - HTTP
        - Implementation
        - Custom Profile
        - DomainFront
        - Multi-User
        - SMB
        - Kill Date
        - macOS
        - GitHub
        - Key Exchange
        - Chaining
        - Price
        - TCP
        - Proxy Aware
        - HTTP3
        - HTTP2
        - Date
        - Evaluator
        - Working Hours
        - Slack
        - FTP
        - Version Reviewed
        - Logging
        - Name
        - License
        - Windows
        - Stego
        - Notes
        - Server
        - Actively Maint.
        - Dashboard
        - DNS
        - Popular Site
        - ICMP
        - IMAP
        - DoH
        - Jitter
        - How-To
        - ATT&CK Mapping
        - Kali
        - Twitter
        - MAPI
        - Site
        - Agent
        - API
        - UI
        - Linux


## Generated Attck Data Structure

The [generated_attck_data.json](https://raw.githubusercontent.com/swimlane/pyattck/master/generated_attck_data.json) has the following base structure. This is purely an example and contains modified/fake data.

```json
   {
       "last_updated": "2019-12-06T15:21:02.175108", 
       "techniques": [
        {
            "technique_id": "T1082", 
            "commands": [
                {
                    "source": "https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx", 
                    "command": "whoami /all /fo list", 
                    "name": "Built-in Windows Command"
                },
                {
                    "source": "atomics/T1033/T1033.yaml", 
                    "command": "cmd.exe /C whoami\nwmic useraccount get /ALL\nquser /SERVER:\"computer1\"\nquser\nqwinsta.exe\" /server:computer1\nqwinsta.exe\nfor /F \"tokens=1,2\" %i in ('qwinsta /server:computer1 ^| findstr \"Active Disc\"') do @echo %i | find /v \"#\" | find /v \"console\" || echo %j > usernames.txt\n@FOR /F %n in (computers.txt) DO @FOR /F \"tokens=1,2\" %i in ('qwinsta /server:%n ^| findstr \"Active Disc\"') do @echo %i | find /v \"#\" | find /v \"console\" || echo %j > usernames.txt\n", 
                    "name": null
                }
            ],
            "command_list": [
                    "ver", 
                    "shell ver", 
                    "set", 
                    "shell set", 
                    "get_env.rb", 
                    "net config workstation",
                    "net config server", 
                    "shell net config workstation",
                    "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
            ], 
            "parsed_datasets": [
                {
                    "Mitre APT3 Adversary Emulation Field Manual": {"Category": "T1033", "Built-in Windows Command": "whoami /all /fo list", "Cobalt Strike": "shell whoami /all /fo list", "Description": "Get current user information, SID, domain, groups the user belongs to, security privs of the user", "Metasploit": "getuid"}
                },
                {
                    "Atomic Red Team Test - System Owner/User Discovery": {"display_name": "System Owner/User Discovery", "atomic_tests": [{"executor": {"elevation_required": false, "command": "cmd.exe /C whoami\nwmic useraccount get /ALL\nquser /SERVER:\"#{computer_name}\"\nquser\nqwinsta.exe\" /server:#{computer_name}\nqwinsta.exe\nfor /F \"tokens=1,2\" %i in ('qwinsta /server:#{computer_name} ^| findstr \"Active Disc\"') do @echo %i | find /v \"#\" | find /v \"console\" || echo %j > usernames.txt\n@FOR /F %n in (computers.txt) DO @FOR /F \"tokens=1,2\" %i in ('qwinsta /server:%n ^| findstr \"Active Disc\"') do @echo %i | find /v \"#\" | find /v \"console\" || echo %j > usernames.txt\n", "name": "command_prompt"}, "supported_platforms": ["windows"], "description": "Identify System owner or users on an endpoint\n", "input_arguments": {"computer_name": {"default": "computer1", "type": "string", "description": "Name of remote computer"}}, "name": "System Owner/User Discovery"}, {"executor": {"elevation_required": false, "command": "users\nw\nwho\n", "name": "sh"}, "supported_platforms": ["linux", "macos"], "description": "Identify System owner or users on an endpoint\n", "name": "System Owner/User Discovery"}], "attack_technique": "T1033"}
                }
            ],
            "queries": [
                {
                    "query": "Sysmon| where EventID == 1 and (process_path contains\"sysinfo.exe\"or process_path contains \"reg.exe\")and process_commandline contains \"reg*query HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Disk\\\\Enum\"", 
                    "product": "Azure Sentinel", 
                    "name": "System Information Discovery"
                },
                {
                    "query": "title: Reconnaissance Activity with Net Command\nid: 2887e914-ce96-435f-8105-593937e90757\nstatus: experimental\ndescription: Detects a set of commands often used in recon stages by different attack groups\nreferences:\n    - https://twitter.com/haroonmeer/status/939099379834658817\n    - https://twitter.com/c_APT_ure/status/939475433711722497\n    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html\nauthor: Florian Roth, Markus Neis\ndate: 2018/08/22\nmodified: 2018/12/11\ntags:\n    - attack.discovery\n    - attack.t1087\n    - attack.t1082\n    - car.2016-03-001\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine:\n            - tasklist\n            - net time\n            - systeminfo\n            - whoami\n            - nbtstat\n            - net start\n            - '*\\net1 start'\n            - qprocess\n            - nslookup\n            - hostname.exe\n            - '*\\net1 user /domain'\n            - '*\\net1 group /domain'\n            - '*\\net1 group \"domain admins\" /domain'\n            - '*\\net1 group \"Exchange Trusted Subsystem\" /domain'\n            - '*\\net1 accounts /domain'\n            - '*\\net1 user net localgroup administrators'\n            - netstat -an\n    timeframe: 15s\n    condition: selection | count() by CommandLine > 4\nfalsepositives:\n    - False positives depend on scripts and administrative tools used in the monitored environment\nlevel: medium", "product": "Atomic Threat Coverage", 
                    "name": "Sigma rule"
                },
                {
                    "query": "(CommandLine=\"tasklist\" OR CommandLine=\"net time\" OR CommandLine=\"systeminfo\" OR CommandLine=\"whoami\" OR CommandLine=\"nbtstat\" OR CommandLine=\"net start\" OR CommandLine=\"*\\\\\\\\net1 start\" OR CommandLine=\"qprocess\" OR CommandLine=\"nslookup\" OR CommandLine=\"hostname.exe\" OR CommandLine=\"*\\\\\\\\net1 user /domain\" OR CommandLine=\"*\\\\\\\\net1 group /domain\" OR CommandLine=\"*\\\\\\\\net1 group \\\\\"domain admins\\\\\" /domain\" OR CommandLine=\"*\\\\\\\\net1 group \\\\\"Exchange Trusted Subsystem\\\\\" /domain\" OR CommandLine=\"*\\\\\\\\net1 accounts /domain\" OR CommandLine=\"*\\\\\\\\net1 user net localgroup administrators\" OR CommandLine=\"netstat -an\") | eventstats count as val by CommandLine| search val > 4", 
                    "product": "Atomic Threat Coverage", 
                    "name": "splunk"
                }
            ],
   }
```

## Sources

First of all, I would like to thank everyone who contributes to open-source projects, especially the maintainers and creators of these projects.  Without them, this capability would not be possible.

This data set is generated from many different sources. As we continue to add more sources, we will continue to add them here.  Again thank you to all of these projects.  In no particular order, `pyattck` utilizes data from the following projects:


* [Mitre ATT&CK APT3 Adversary Emulation Field Manual](https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx)
* [Atomic Red Team (by Red Canary)](https://github.com/redcanaryco/atomic-red-team)
* [Atomic Threat Coverage](https://github.com/atc-project/atomic-threat-coverage)
* [attck_empire (by dstepanic)](https://github.com/dstepanic/attck_empire)
* [sentinel-attack (by BlueTeamLabs)](https://github.com/BlueTeamLabs/sentinel-attack)
* [Litmus_test (by Kirtar22)](https://github.com/Kirtar22/Litmus_Test)
* [nsm-attack (by oxtf)](https://github.com/0xtf/nsm-attack)
* [osquery-attck (by teoseller)](https://github.com/teoseller/osquery-attck)
* [Mitre Stockpile](https://github.com/mitre/stockpile)
* [SysmonHunter (by baronpan)](https://github.com/baronpan/SysmonHunter)
* [ThreatHunting-Book (by 12306Bro)](https://github.com/12306Bro/Threathunting-book)
* [threat_hunting_tables (by dwestgard)](https://github.com/dwestgard/threat_hunting_tables)
* [APT Groups & Operations](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit#gid=1864660085)
* [C2Matrix (by @jorgeorchilles, @brysonbort, @adam_mashinchi)](https://www.thec2matrix.com/)
