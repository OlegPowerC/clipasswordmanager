CLI Password manager.
License - GPL.
Data write to JSON file.
I use AES encryption for protection sensivity data (Passwords).
When datastore file create, I make sha hash of the master password and encrypt it by AES use masterpasword for make AES key.
When we open datastore, we decrypt this encrypted hash and compare to calculated hash.
If it equal then password is valid.
I make simple stupid cli interface but it work perfect for me.
You can change anything but please send me Your modification.
Thank You.
Example command:
    add resource:
        clipm.exe -keystore mainkeystore.json -add -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$1 -p2 CiEnableP@$$1
    dlete resource:
        clipm.exe -keystore mainkeystore.json -delete -g Group1 -n CiscoSw_01
    dlete empty group:
            clipm.exe -keystore mainkeystore.json -deletegroup -g Group1
    edit resource:
        clipm.exe -keystore mainkeystore.json -edit -g Group1 -n CiscoSw_01 -i 192.168.1.58 -u CiscoAdm -p CiP@$$2 -p2 CiEnableP@$$2
    show resource:
        clipm.exe -keystore mainkeystore.json -show -g Group1 -n CiscoSw_01
    list groups and resources:
            clipm.exe -keystore mainkeystore.json -l
            example:
            clipm.exe -keystore test.json -l
            Keystore will be: test.json
            Password:
            List groups and resources
            -------------------------
            |-- Default
            |  |-- Demoresource
            |-- cisco
               |-- core_sw01

PS:
What I will want to add in the future:
1. Backup file. (added backup file to "backup" folder, after open keystore)
2. Check IP and FQDN data (added check IP addresses but not FQDN)
3. More tests (found bug when delete group and fixed it)
