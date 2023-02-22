# CLI Password manager
License - GPL
### Data writes to JSON file
I use AES encryption for protection sensivity data (Passwords).
When datastore file create, I make sha hash of the master password and encrypt it by AES use masterpasword for make AES key.
When we open datastore, we decrypt this encrypted hash and compare to calculated hash.
If it equal then password is valid.
I make simple stupid cli interface but it work perfect for me.
You can change anything but please send me Your modification.
Thank You.
____
### Parameters:
**-add** Add resource\
**-copy** string Provide new name of the resource\
**-delete** Delete resource\
**-deletegroup** Delete empty group\
**-edit** Edit resource\
**-find** string Find resources by text\
**-passwd** change keystore password\
**-fqdn** string Resource FQDN adress\
**-g** string Group name (default "Default")\
**-i** string Resource IP adress\
**-keystore** string Name of the keystore - file name like: keystore1.json (default "Resources.json")\
**-l** List all\
**-lg** List group\
**-lrg** List resources in the group Provide group name -g for list resources in this group\
**-n** string Resource name\
**-p** string Password\
**-p2** string Second password (for example, Cisco enable password)\
**-show** Provide group name -g and resource name -n\
**-u** string Username<br>
**-snmpver** int Snmp version, 2 or 3<br>
**-snmpv3u** string SNMP v3 username<br>
**-a** string SNMPv3 auth protocol, md5 sha or none<br>
**-A** string SNMPv3 auth key<br>
**-x** string SNMPv3 priv protocol<br>
**-X** string SNMPv3 priv key<br>
**-d** string Description<br>
**-h** Print help
____
### Example command:
#### add resource:
clipm.exe -keystore mainkeystore.json -add -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$1 -p2 CiEnableP@$$1 -d "CiscoSw"<br>
#### dlete resource:
clipm.exe -keystore mainkeystore.json -delete -g Group1 -n CiscoSw_01<br>
#### dlete empty group:
clipm.exe -keystore mainkeystore.json -deletegroup -g Group1<br>
#### edit resource:
clipm.exe -keystore mainkeystore.json -edit -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$2 -p2 CiEnableP@$$2 -d "CiscoSw"<br>
#### show resource:
clipm.exe -keystore mainkeystore.json -show -g Group1 -n CiscoSw_01
#### list groups and resources:
clipm.exe -keystore mainkeystore.json -l
#### example:
            clipm.exe -keystore test.json -l
            Keystore will be: test.json
            Password:
            List groups and resources
            -------------------------
            |-- Default
            | |-- Demoresource
            |-- cisco
              |-- core_sw01
#### find resources:
clipm.exe -keystore mainkeystore.json -find 192.168.0.1\
Find resource by text "192.168.0.1" in all field except password, no case sensivity
Resources int group: Default

            Name            : Demoresource
            IP address      : 192.168.0.1
            FQDN            : DemoCisco.yourdomain.local
            Username        : Cisco
            Password        : Cisco
            Second password : Cisco123%
            Description     : Cisco switch

In all command, You can leave keystore parameter (default keystore will be use)
____
### New features:
added parameter Default_keystore in settings.json for provide default keystore name (json file name)\
added parameter Create_backups in settings.json. If this parameter 0 - no backups will be make

### Binary:
Windows: clipm.exe\
Linux: clipm (will need make it executable by chmod +x clipm)