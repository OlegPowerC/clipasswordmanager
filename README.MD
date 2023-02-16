# CLI Password manager
License - GPL
### Data write to JSON file
I use AES encryption for protection sensivity data (Passwords).
When datastore file create, I make sha hash of the master password and encrypt it by AES use masterpasword for make AES key.
When we open datastore, we decrypt this encrypted hash and compare to calculated hash.
If it equal then password is valid.
I make simple stupid cli interface but it work perfect for me.
You can change anything but please send me Your modification.
Thank You.  
Parameters:\
-add Add resource\
-copy string Provide new name of the resource<br/>
-delete Delete resource<br/>
-deletegroup Delete empty group<br/>
-edit Edit resource\
-find string Find resources by text\
-passwd change keystore password\
-fqdn string Resource FQDN adress<br>
-g string Group name (default "Default")<br>
-i string Resource IP adress<br>
-keystore string Name of the keystore - file name like: keystore1.json (default "Resources.json")<br>
-l List all<br>
-lg List group <br>
-lrg List resources in the group Provide group name -g for list resources in this group<br>
-n string Resource name<br>
-p string Password<br>
-p2 string Second password (for example, Cisco enable password)<br>
-show Provide group name -g and resource name -n<br>
-u string Username<br>
-snmpver int Snmp version, 2 or 3<br>
-snmpv3u string SNMP v3 username<br>
-a string SNMPv3 auth protocol, md5 sha or none<br>
-A string SNMPv3 auth key<br>
-x string SNMPv3 priv protocol<br>
-X string SNMPv3 priv key<br>
-d string Description<br>
-h Print help

Example command:<br>
    add resource:<br>
        clipm.exe -keystore mainkeystore.json -add -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$1 -p2 CiEnableP@$$1 -d "CiscoSw"<br>
    dlete resource:<br>
        clipm.exe -keystore mainkeystore.json -delete -g Group1 -n CiscoSw_01<br>
    dlete empty group:<br>
            clipm.exe -keystore mainkeystore.json -deletegroup -g Group1<br>
    edit resource:<br>
        clipm.exe -keystore mainkeystore.json -edit -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$2 -p2 CiEnableP@$$2 -d "CiscoSw"<br>
    show resource:<br>
        clipm.exe -keystore mainkeystore.json -show -g Group1 -n CiscoSw_01<br>
    list groups and resources:<br>
            clipm.exe -keystore mainkeystore.json -l<br>
            example:<br>
            clipm.exe -keystore test.json -l<br>
            Keystore will be: test.json<br>
            Password:<br>
            List groups and resources<br>
            -------------------------<br>
            |-- Default<br>
            |&nbsp;&nbsp;|-- Demoresource<br>
            |-- cisco<br>
            &nbsp;&nbsp;|-- core_sw01<br>
    find resources:<br>
        clipm.exe -keystore mainkeystore.json -find 192.168.0.1<br>
            Find resource by text "192.168.0.1"in all field except password, no case sensivity<br>
            ---
            Resources int group: Default<br>
            ---
            Name            : Demoresource<br>
            IP address      : 192.168.0.1<br>
            FQDN            : DemoCisco.yourdomain.local<br>
            Username        : Cisco<br>
            Password        : Cisco<br>
            Second password : Cisco123%<br>
            Description     : Cisco switch<br>
    In all command, You can leave keystore parameter (default keystore will be use)<br>
<br>
New features:<br>
    added parameter Default_keystore in settings.json for provide default keystore name (json file name)<br>
    added parameter Create_backups in settings.json. If this parameter 0 - no backups will be make<br>
<br>
Binary:<br>
Windows: clipm.exe<br>
Linux: clipm (will need make it executable by chmod +h clipm)<br>