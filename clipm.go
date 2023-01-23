package main

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	Psstr "github.com/OlegPowerC/aespassstore"
	CheckIpAddrs "github.com/OlegPowerC/validateip"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type KeystoreData struct {
	Encryptedpasswords bool    `json:"encryptedpasswords" xml:"encryptedpasswords"`
	Magicphrase        string  `json:"magicphrase" xml:"magicphrase"`
	Groups             []Group `json:"groups"`
}

type Settings struct {
	Default_keystore string `json:"Default_keystore"`
	Create_backups   int    `json:"Create_backups"`
}

type UnXmlKeystoreData struct {
	Groups []Group `json:"groups" xml:"groups"`
}

type ResourceItem struct {
	Ipaddr          string `json:"ipaddr" xml:"ipaddr"`
	Name            string `json:"name" xml:"name"`
	FQDN            string `json:"fqdn" xml:"fqdn"`
	Username        string `json:"username" xml:"username"`
	Password        string `json:"password" xml:"password"`
	EnablePassword  string `json:"enable_password" xml:"enable_password"`
	SNMPver         int    `json:"snmp_ver" xml:"snmp_ver"`
	SNMPv3USM       string `json:"snmpv3_usm" xml:"snmpv3_usm"`
	SNMPv3AuthProto string `json:"snmpv3_auth_proto"`
	SNMPv3Auth      string `json:"snmpv3_auth"`
	SNMPv3PrivProto string `json:"snmpv3_priv_proto" xml:"snmpv3_priv_proto"`
	SNMPv3Priv      string `json:"snmpv3_priv" xml:"snmpv3_priv"`
	SNMPv2Community string `json:"snmpv2_community" xml:"snmpv2_community"`
	Description     string `json:"description" xml:"description"`
}

type Group struct {
	Groupname string         `json:"groupname" xml:"groupname"`
	Resources []ResourceItem `json:"resources" xml:"resources"`
}

func AddData(GroupName string,
	Name string,
	Ip string,
	Fqdn string,
	Username string,
	Password string,
	Password2 string,
	SNMPver int,
	SNMPv3USM string,
	SNMPv3AuthProto string,
	SNMPv3Auth string,
	SNMPv3PrivProto string,
	SNMPv3Priv string,
	SNMPv2Community string,
	Description string,
	KSData *KeystoreData,
	keystorepassword string) error {
	EncryptedPassword1, _ := EncryptPassword(Password, keystorepassword)
	EncryptedPassword2, _ := EncryptPassword(Password2, keystorepassword)
	EncryptedSnmpAuth, _ := EncryptPassword(SNMPv3Auth, keystorepassword)
	EncryptedSnmpPriv, _ := EncryptPassword(SNMPv3Priv, keystorepassword)
	EncryptedSnmpCommunity, _ := EncryptPassword(SNMPv2Community, keystorepassword)

	var ResourceItemNewData ResourceItem
	FGindFinded := -1

	if len(Name) < 3 {
		return fmt.Errorf("Lenght of the Name must be 3+ symols")
	}
	for Gind, Gval := range (*KSData).Groups {
		if GroupName == Gval.Groupname {
			FGindFinded = Gind
			break
		}
	}

	if len(Ip) > 0 {
		ChIerr := CheckIpAddrs.CheckSingleIp(Ip)
		if ChIerr != nil {
			return ChIerr
		}
	}

	ResourceItemNewData.Name = Name
	ResourceItemNewData.Ipaddr = Ip
	ResourceItemNewData.FQDN = Fqdn
	ResourceItemNewData.Username = Username
	ResourceItemNewData.Password = EncryptedPassword1
	ResourceItemNewData.EnablePassword = EncryptedPassword2
	ResourceItemNewData.SNMPver = SNMPver
	ResourceItemNewData.SNMPv3USM = SNMPv3USM
	ResourceItemNewData.SNMPv3AuthProto = SNMPv3AuthProto
	ResourceItemNewData.SNMPv3Auth = EncryptedSnmpAuth
	ResourceItemNewData.SNMPv3PrivProto = SNMPv3PrivProto
	ResourceItemNewData.SNMPv3Priv = EncryptedSnmpPriv
	ResourceItemNewData.SNMPv2Community = EncryptedSnmpCommunity
	ResourceItemNewData.Description = Description
	if FGindFinded >= 0 {
		for _, ResourceCheck := range (*KSData).Groups[FGindFinded].Resources {
			if ResourceCheck.Name == Name {
				RetErr := fmt.Errorf("Resource %s, in group %s, already exsist", GroupName, Name)
				return RetErr
			}

		}
		(*KSData).Groups[FGindFinded].Resources = append((*KSData).Groups[FGindFinded].Resources, ResourceItemNewData)
	} else {
		ResourcesNew := make([]ResourceItem, 0)
		ResourcesNew = append(ResourcesNew, ResourceItemNewData)
		(*KSData).Groups = append((*KSData).Groups, Group{Groupname: GroupName, Resources: ResourcesNew})
	}
	return nil
}

type FindRes struct {
	Groupname           string
	ResourcesInTheGroup []ResourceItem
}

func EditResource(GroupName string,
	Name string,
	Ip string,
	Fqdn string,
	Username string,
	Password string,
	Password2 string,
	SNMPver int,
	SNMPv3USM string,
	SNMPv3AuthProto string,
	SNMPv3Auth string,
	SNMPv3PrivProto string,
	SNMPv3Priv string,
	SNMPv2Community string,
	Description string,
	KSdata *KeystoreData,
	keystorepassword string) error {
	EncryptedPassword1, _ := EncryptPassword(Password, keystorepassword)
	EncryptedPassword2, _ := EncryptPassword(Password2, keystorepassword)
	EncryptedSnmpAuth, _ := EncryptPassword(SNMPv3Auth, keystorepassword)
	EncryptedSnmpPriv, _ := EncryptPassword(SNMPv3Priv, keystorepassword)
	EncryptedSnmpCommunity, _ := EncryptPassword(SNMPv2Community, keystorepassword)

	if len(Name) < 3 {
		return fmt.Errorf("No name of the resource")
	}
	if len(GroupName) < 3 {
		return fmt.Errorf("No group name")
	}

	if len(Ip) > 0 {
		ChIerr := CheckIpAddrs.CheckSingleIp(Ip)
		if ChIerr != nil {
			return ChIerr
		}
	}

	FGindFinded := -1
	FRindFinded := -1
	for Gind, Gval := range (*KSdata).Groups {
		if GroupName == Gval.Groupname {
			FGindFinded = Gind
			break
		}
	}
	if FGindFinded == -1 {
		return fmt.Errorf("Group %s not found", GroupName)
	} else {
		for rind, rdata := range (*KSdata).Groups[FGindFinded].Resources {
			if rdata.Name == Name {
				FRindFinded = rind
				break
			}
		}
	}
	if FRindFinded != -1 {
		//Если запись найдена
		if len(Ip) > 7 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Ipaddr = Ip
		}

		if len(Fqdn) > 0 {
			if len(Fqdn) >= 7 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].FQDN = Fqdn
			} else {
				if len(Fqdn) == 1 && Fqdn == " " {
					(*KSdata).Groups[FGindFinded].Resources[FRindFinded].FQDN = ""
				} else {
					fmt.Println("FQDN length must at least 7 characters long")
					os.Exit(1)
				}
			}
		}

		if len(Username) > 0 {
			if len(Username) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Username = Username
			} else {
				fmt.Println("Username length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(SNMPv3USM) > 0 {
			if len(SNMPv3USM) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv3USM = SNMPv3USM
			} else {
				fmt.Println("SNMP v3 Username length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(Password) > 0 {
			if len(Password) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Password = EncryptedPassword1
			} else {
				fmt.Println("Password length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(Password2) > 0 {
			if len(Password2) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].EnablePassword = EncryptedPassword2
			} else {
				fmt.Println("Password2 length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if SNMPver > 0 && SNMPver < 4 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPver = SNMPver
		}

		if len(SNMPv3AuthProto) > 0 {
			SNMPv3AuthProto = strings.ToLower(SNMPv3AuthProto)
			if SNMPv3AuthProto != "md5" && SNMPv3AuthProto != "sha" && SNMPv3AuthProto != "none" {
				fmt.Println("SNMPv3 auth protocol must be md5, sha or none, but you provide:", SNMPv3AuthProto)
				os.Exit(1)
			} else {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv3AuthProto = SNMPv3AuthProto
			}
		}

		if len(SNMPv3PrivProto) > 0 {
			SNMPv3PrivProto = strings.ToLower(SNMPv3PrivProto)
			if SNMPv3PrivProto != "des" && SNMPv3PrivProto != "aes" && SNMPv3PrivProto != "none" {
				fmt.Println("SNMPv3 priv protocol must be des, aes or none but you provide:", SNMPv3PrivProto)
				os.Exit(1)
			} else {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv3PrivProto = SNMPv3PrivProto
			}
		}

		if len(SNMPv3Auth) > 0 {
			if len(SNMPv3Auth) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv3Auth = EncryptedSnmpAuth
			} else {
				fmt.Println("SNMPv3 auth key length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(SNMPv3Priv) > 0 {
			if len(SNMPv3Priv) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv3Priv = EncryptedSnmpPriv
			} else {
				fmt.Println("SNMPv3 priv key length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(SNMPv2Community) > 0 {
			if len(SNMPv2Community) >= 3 {
				(*KSdata).Groups[FGindFinded].Resources[FRindFinded].SNMPv2Community = EncryptedSnmpCommunity
			} else {
				fmt.Println("SNMPv2 community string length must at least 3 characters long")
				os.Exit(1)
			}
		}

		if len(Description) > 0 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Description = Description
		}
	}
	if FRindFinded == -1 {
		return fmt.Errorf("No resource found")
	}
	return nil
}

func CopyResource(GroupName string,
	Name string,
	Ip string,
	Fqdn string,
	Username string,
	Password string,
	Password2 string,
	SNMPver int,
	SNMPv3USM string,
	SNMPv3AuthProto string,
	SNMPv3Auth string,
	SNMPv3PrivProto string,
	SNMPv3Priv string,
	SNMPv2Community string,
	Description string,
	KSdata *KeystoreData,
	keystorepassword string,
	NewName string) error {
	//EncryptedPassword1, _ := EncryptPassword(Password, keystorepassword)
	//EncryptedPassword2, _ := EncryptPassword(Password2, keystorepassword)

	if len(Name) < 3 {
		return fmt.Errorf("No name of the resource")
	}
	if len(GroupName) < 3 {
		return fmt.Errorf("No group name")
	}

	if len(Ip) > 0 {
		ChIerr := CheckIpAddrs.CheckSingleIp(Ip)
		if ChIerr != nil {
			return ChIerr
		}
	}

	FGindFinded := -1
	FRindFinded := -1
	for Gind, Gval := range (*KSdata).Groups {
		if GroupName == Gval.Groupname {
			FGindFinded = Gind
			break
		}
	}
	if FGindFinded == -1 {
		return fmt.Errorf("Group %s not found", GroupName)
	} else {
		for rind, rdata := range (*KSdata).Groups[FGindFinded].Resources {
			if rdata.Name == Name {
				FRindFinded = rind
				break
			}
		}
	}
	if FRindFinded != -1 {
		//Если запись найдена
		var NewResource ResourceItem
		NewResource = (*KSdata).Groups[FGindFinded].Resources[FRindFinded]
		if len(NewName) < 3 {
			return fmt.Errorf("Wrong new name")
		}

		NewResource.Name = NewName

		if len(Ip) > 0 {
			NewResource.Ipaddr = Ip
		}
		if len(Fqdn) > 0 {
			NewResource.FQDN = Fqdn
		}
		if len(Username) > 0 {
			NewResource.Username = Username
		}
		if len(SNMPv3USM) > 0 {
			NewResource.SNMPv3USM = SNMPv3USM
		}
		if SNMPver > 0 {
			NewResource.SNMPver = SNMPver
		}
		if len(SNMPv3AuthProto) > 0 {
			NewResource.SNMPv3AuthProto = SNMPv3AuthProto
		}
		if len(SNMPv3PrivProto) > 0 {
			NewResource.SNMPv3PrivProto = SNMPv3PrivProto
		}
		if len(NewResource.Password) > 8 {
			NewResource.Password, _ = DecryptPassword(NewResource.Password, keystorepassword)
		}
		if len(NewResource.EnablePassword) > 8 {
			NewResource.EnablePassword, _ = DecryptPassword(NewResource.EnablePassword, keystorepassword)
		}
		if len(NewResource.SNMPv3Auth) > 8 {
			NewResource.SNMPv3Auth, _ = DecryptPassword(NewResource.SNMPv3Auth, keystorepassword)
		}
		if len(NewResource.SNMPv3Priv) > 8 {
			NewResource.SNMPv3Priv, _ = DecryptPassword(NewResource.SNMPv3Priv, keystorepassword)
		}
		if len(NewResource.SNMPv2Community) > 8 {
			NewResource.SNMPv2Community, _ = DecryptPassword(NewResource.SNMPv2Community, keystorepassword)
		}

		if len(Password) >= 3 {
			NewResource.Password = Password
		}
		if len(Password2) >= 3 {
			NewResource.EnablePassword = Password2
		}
		if len(SNMPv3Auth) >= 3 {
			NewResource.Password = SNMPv3Auth
		}
		if len(SNMPv3Priv) >= 3 {
			NewResource.EnablePassword = SNMPv3Priv
		}
		if len(SNMPv2Community) >= 3 {
			NewResource.EnablePassword = SNMPv2Community
		}

		if len(Description) >= 1 {
			NewResource.Description = Description
		}

		AddErr := AddData(GroupName,
			NewResource.Name,
			NewResource.Ipaddr,
			NewResource.FQDN,
			NewResource.Username,
			NewResource.Password,
			NewResource.EnablePassword,
			NewResource.SNMPver,
			NewResource.SNMPv3USM,
			NewResource.SNMPv3AuthProto,
			NewResource.SNMPv3Auth,
			NewResource.SNMPv3PrivProto,
			NewResource.SNMPv3Priv,
			NewResource.SNMPv2Community,
			NewResource.Description,
			KSdata, keystorepassword)
		if AddErr != nil {
			return fmt.Errorf("Error while adding: %s", AddErr)
		}
	}
	if FRindFinded == -1 {
		return fmt.Errorf("No resource found")
	}
	return nil
}

func DeleteResource(ResourceName string, GroupName string, KSdata *KeystoreData) error {
	if len(ResourceName) < 3 {
		return fmt.Errorf("No name of the resource")
	}
	FGindFinded := -1
	FRindFinded := -1
	for Gind, Gval := range (*KSdata).Groups {
		if GroupName == Gval.Groupname {
			FGindFinded = Gind
			break
		}
	}
	if FGindFinded == -1 {
		return fmt.Errorf("Group %s not found", GroupName)
	} else {
		for rind, rdata := range (*KSdata).Groups[FGindFinded].Resources {
			if rdata.Name == ResourceName {
				FRindFinded = rind
				break
			}
		}
	}
	if FRindFinded != -1 {
		//Если запись найдена и при этом длина записей равна 1 то удаляем все элементы
		if len((*KSdata).Groups[FGindFinded].Resources) == 1 {
			(*KSdata).Groups[FGindFinded].Resources = make([]ResourceItem, 0)
		} else {
			//если же элементов больше одного то если элемент первый просто укоротим список слева
			if FRindFinded == 0 {
				(*KSdata).Groups[FGindFinded].Resources = (*KSdata).Groups[FGindFinded].Resources[FRindFinded+1:]
				return nil
			}
			//если элемент последний то укоротим справа
			if FRindFinded == len((*KSdata).Groups[FGindFinded].Resources)-1 {
				(*KSdata).Groups[FGindFinded].Resources = (*KSdata).Groups[FGindFinded].Resources[:FRindFinded]
				return nil
			}

			if FRindFinded > 0 && FRindFinded < len((*KSdata).Groups[FGindFinded].Resources)-1 {
				FRes := (*KSdata).Groups[FGindFinded].Resources[:FRindFinded]
				SRes := (*KSdata).Groups[FGindFinded].Resources[FRindFinded+1:]
				(*KSdata).Groups[FGindFinded].Resources = make([]ResourceItem, 0)
				(*KSdata).Groups[FGindFinded].Resources = append((*KSdata).Groups[FGindFinded].Resources, FRes...)
				(*KSdata).Groups[FGindFinded].Resources = append((*KSdata).Groups[FGindFinded].Resources, SRes...)
				return nil
			}
		}
	}
	if FRindFinded == -1 {
		return fmt.Errorf("No resource found")
	}
	return nil
}

func DeleteEmptyGroup(GroupName string, KSdata *KeystoreData) error {
	FGindFinded := -1
	IsEmptyGroup := false
	for Gind, Gval := range (*KSdata).Groups {
		if GroupName == Gval.Groupname {
			FGindFinded = Gind
			break
		}
	}
	if FGindFinded == -1 {
		return fmt.Errorf("Group %s not found", GroupName)
	} else {
		if len((*KSdata).Groups[FGindFinded].Resources) == 0 {
			IsEmptyGroup = true
		}
	}
	if IsEmptyGroup {
		//Если группа аустая
		if len((*KSdata).Groups) == 1 {
			(*KSdata).Groups = make([]Group, 0)
		} else {
			//если же элементов больше одного то если элемент первый просто укоротим список слева
			if FGindFinded == 0 {
				(*KSdata).Groups = (*KSdata).Groups[FGindFinded+1:]
				return nil
			}
			//если элемент последний то укоротим справа
			if FGindFinded == len((*KSdata).Groups)-1 {
				(*KSdata).Groups = (*KSdata).Groups[:FGindFinded]
				return nil
			}

			if FGindFinded > 0 && FGindFinded < len((*KSdata).Groups)-1 {
				FGroup := (*KSdata).Groups[:FGindFinded]
				SGroup := (*KSdata).Groups[FGindFinded+1:]
				(*KSdata).Groups = make([]Group, 0)
				(*KSdata).Groups = append((*KSdata).Groups, FGroup...)
				(*KSdata).Groups = append((*KSdata).Groups, SGroup...)
				return nil
			}
		}
	}
	if !IsEmptyGroup {
		return fmt.Errorf("Group not empty")
	}
	return nil
}

func EncryptPassword(PlainPassword string, Masterkey string) (EncryptedPasswordBase64 string, err error) {
	if len(Masterkey) <= 3 {
		return PlainPassword, fmt.Errorf("Password to short")
	}
	CIPHER_KEYE := []byte(Masterkey)
	CIPHER_KEY := make([]byte, 16)
	lenck := len(CIPHER_KEYE)
	if lenck == 16 {
		CIPHER_KEY = CIPHER_KEYE
	}
	if lenck < 16 {
		copy(CIPHER_KEY[:lenck], CIPHER_KEYE)
	}
	if lenck > 16 {
		copy(CIPHER_KEY, CIPHER_KEYE[:16])
	}
	EncryptedPassword, EncryptErr := Psstr.Encrypt(CIPHER_KEY, PlainPassword)
	if EncryptErr != nil {
		return "", EncryptErr
	} else {
		return EncryptedPassword, EncryptErr
	}
}

func DecryptPassword(EncryptedPassword string, Masterkey string) (PlainTextPassword string, err error) {
	CIPHER_KEYE := []byte(Masterkey)
	CIPHER_KEY := make([]byte, 16)
	lenck := len(CIPHER_KEYE)
	if lenck == 16 {
		CIPHER_KEY = CIPHER_KEYE
	}
	if lenck < 16 {
		copy(CIPHER_KEY[:lenck], CIPHER_KEYE)
	}
	if lenck > 16 {
		copy(CIPHER_KEY, CIPHER_KEYE[:16])
	}
	if len(EncryptedPassword) > 1 {
		DecryptedPassword, DecryptErr := Psstr.Decrypt(CIPHER_KEY, EncryptedPassword)
		if DecryptErr != nil {
			return "", DecryptErr
		} else {
			return DecryptedPassword, DecryptErr
		}
	} else {
		return "", fmt.Errorf("Password to short")
	}
}

func CheckFlag(FlagName string) bool {
	FlagFound := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == FlagName {
			FlagFound = true
		}
	})
	return FlagFound
}

func checkFile(filename string, keystorepassword string, doBackup bool) (error, *KeystoreData) {
	backupdirectory := "backups"
	pathseparator := "/"
	if runtime.GOOS == "windows" {
		pathseparator = "\\"
	}
	_, err := os.Stat(filename)
	FirstGroups := make([]Group, 0)
	var FJSdata KeystoreData
	FJSdata.Groups = FirstGroups

	PasswordHash := sha1.New()
	PasswordHash.Reset()
	Hash := PasswordHash.Sum([]byte(keystorepassword))

	if os.IsNotExist(err) {
		//Файл (хранилище) не найден
		fmt.Println("No keystore", filename, "exsist - make it")
		if len(keystorepassword) > 3 {
			FJSdata.Encryptedpasswords = true
			FJSdata.Magicphrase, _ = EncryptPassword(string(Hash), keystorepassword)
		} else {
			FJSdata.Encryptedpasswords = false
			FJSdata.Magicphrase = ""
		}
		AddData("Default",
			"Demoresource",
			"192.168.0.1",
			"DemoCisco.yourdomain.local",
			"Cisco",
			"Cisco",
			"Cisco123%", 3,
			"snmpv3-user",
			"sha",
			"authkey123",
			"aes",
			"privkey123",
			"",
			"Demo resource",
			&FJSdata, keystorepassword)

		jsondata, _ := json.Marshal(&FJSdata)
		_, err := os.Create(filename)
		if err != nil {
			return err, nil
		} else {
			err = ioutil.WriteFile(filename, jsondata, 0644)
			if err != nil {
				return err, nil
			} else {
				filebytes, err := ioutil.ReadFile(filename)
				if err != nil {
					return err, nil
				} else {
					json.Unmarshal(filebytes, &FJSdata)
					return nil, &FJSdata
				}
			}
		}
	} else {
		//Файл существует. После его чтения, сразу создаем резервную копию
		filebytes, err := ioutil.ReadFile(filename)
		if doBackup {
			BackupFileName := fmt.Sprintf("%s%s%s_%s.back", backupdirectory, pathseparator, filename, time.Now().Format("2006-01-02_15_04_05"))
			backupwriteerror := ioutil.WriteFile(BackupFileName, filebytes, 0644)
			if backupwriteerror != nil {
				fmt.Println("Error make backup:", backupwriteerror)
			}
		}

		if err != nil {
			return err, nil
		} else {
			json.Unmarshal(filebytes, &FJSdata)
			DeMp, _ := DecryptPassword(FJSdata.Magicphrase, keystorepassword)
			if DeMp != string(Hash) {
				fmt.Println("Invalid password")
				os.Exit(1)
			}
			return nil, &FJSdata
		}
	}
	return nil, nil
}

func WriteData(KeystoreName string, Gr *KeystoreData) error {
	jsondata, _ := json.Marshal(Gr)
	err := ioutil.WriteFile(KeystoreName, jsondata, 0644)
	return err
}

func MakePlainetxXML(UnexcryptedXmlFilename string, Gr *KeystoreData, KeystorePassword string) error {
	var XMLData UnXmlKeystoreData
	XMLData.Groups = make([]Group, 0)
	XMLItems := make([]Group, 0)
	var XMLitem Group
	for _, GrName := range Gr.Groups {
		var XMLResource ResourceItem
		XMLSources := make([]ResourceItem, 0)
		XMLitem.Groupname = GrName.Groupname
		for _, Res := range GrName.Resources {
			XMLResource.FQDN = Res.FQDN
			XMLResource.Name = Res.Name
			XMLResource.Ipaddr = Res.Ipaddr
			XMLResource.Username = Res.Username
			XMLResource.Password, _ = DecryptPassword(Res.Password, KeystorePassword)
			XMLResource.EnablePassword, _ = DecryptPassword(Res.EnablePassword, KeystorePassword)
			XMLResource.Description = Res.Description
			XMLSources = append(XMLSources, XMLResource)
		}
		XMLitem.Resources = XMLSources
		XMLItems = append(XMLItems, XMLitem)
	}
	XMLData.Groups = XMLItems
	if len(XMLItems) > 0 {
		jsondata, _ := xml.Marshal(&XMLData)
		_, err := os.Create(UnexcryptedXmlFilename)
		if err != nil {
			return err
		} else {
			err = ioutil.WriteFile(UnexcryptedXmlFilename, jsondata, 0644)
		}
	}
	return nil
}

func ChangePassword(Gr *KeystoreData, KeystoreOldPassword string, KeystoreNewPassword string) error {
	for GrIndex, GrName := range Gr.Groups {
		for ResIndex, Res := range GrName.Resources {
			Password, _ := DecryptPassword(Res.Password, KeystoreOldPassword)
			Password2, _ := DecryptPassword(Res.EnablePassword, KeystoreOldPassword)
			SNMPv3Auth, _ := DecryptPassword(Res.SNMPv3Auth, KeystoreOldPassword)
			SNMPv3Priv, _ := DecryptPassword(Res.SNMPv3Priv, KeystoreOldPassword)
			SNMPv2Community, _ := DecryptPassword(Res.SNMPv2Community, KeystoreOldPassword)

			NewEncpassword, NewEncErrpassword := EncryptPassword(Password, KeystoreNewPassword)
			if NewEncErrpassword != nil {
				return NewEncErrpassword
			}
			NewEncpassword2, NewEncErrpassword2 := EncryptPassword(Password2, KeystoreNewPassword)
			if NewEncErrpassword2 != nil {
				return NewEncErrpassword2
			}
			NewSNMPv3Auth, NewSNMPv3AuthErr := EncryptPassword(SNMPv3Auth, KeystoreNewPassword)
			if NewSNMPv3AuthErr != nil {
				return NewSNMPv3AuthErr
			}
			NewSNMPv3Priv, NewSNMPv3PrivErr := EncryptPassword(SNMPv3Priv, KeystoreNewPassword)
			if NewSNMPv3PrivErr != nil {
				return NewSNMPv3PrivErr
			}
			NewSNMPv2Community, NewSNMPv2CommunityErr := EncryptPassword(SNMPv2Community, KeystoreNewPassword)
			if NewSNMPv2CommunityErr != nil {
				return NewSNMPv2CommunityErr
			}

			Gr.Groups[GrIndex].Resources[ResIndex].Password = NewEncpassword
			Gr.Groups[GrIndex].Resources[ResIndex].EnablePassword = NewEncpassword2
			Gr.Groups[GrIndex].Resources[ResIndex].SNMPv3Auth = NewSNMPv3Auth
			Gr.Groups[GrIndex].Resources[ResIndex].SNMPv3Priv = NewSNMPv3Priv
			Gr.Groups[GrIndex].Resources[ResIndex].SNMPv2Community = NewSNMPv2Community
		}
	}
	PasswordHash := sha1.New()
	PasswordHash.Reset()
	Hash := PasswordHash.Sum([]byte(KeystoreNewPassword))

	Gr.Magicphrase, _ = EncryptPassword(string(Hash), KeystoreNewPassword)
	return nil
}

func ShowRes(CurrentResourceInGroup ResourceItem, KeystorePassword string) {
	PlainPassword, _ := DecryptPassword(CurrentResourceInGroup.Password, KeystorePassword)
	PlainPassword2, _ := DecryptPassword(CurrentResourceInGroup.EnablePassword, KeystorePassword)
	PlainSNMPv3Auth, _ := DecryptPassword(CurrentResourceInGroup.SNMPv3Auth, KeystorePassword)
	PlainSNMPv3priv, _ := DecryptPassword(CurrentResourceInGroup.SNMPv3Priv, KeystorePassword)
	PlainSNMPv2Community, _ := DecryptPassword(CurrentResourceInGroup.SNMPv2Community, KeystorePassword)
	fmt.Println("Name\t\t:", CurrentResourceInGroup.Name)
	fmt.Println("IP address\t:", CurrentResourceInGroup.Ipaddr)
	fmt.Println("FQDN\t\t:", CurrentResourceInGroup.FQDN)
	fmt.Println("Username\t:", CurrentResourceInGroup.Username)
	fmt.Println("Password\t:", PlainPassword)
	fmt.Println("Enable password\t:", PlainPassword2)
	fmt.Println("SNMP ver\t:", CurrentResourceInGroup.SNMPver)
	fmt.Println("SNMPv3 User\t:", CurrentResourceInGroup.SNMPv3USM)
	fmt.Println("SNMPv3 Auth\t:", CurrentResourceInGroup.SNMPv3AuthProto)
	fmt.Println("SNMPv3 Auth key\t:", PlainSNMPv3Auth)
	fmt.Println("SNMPv3 Priv\t:", CurrentResourceInGroup.SNMPv3PrivProto)
	fmt.Println("SNMPv3 Priv key\t:", PlainSNMPv3priv)
	fmt.Println("SNMP Community\t:", PlainSNMPv2Community)
	fmt.Println("Description\t:", CurrentResourceInGroup.Description)
}

func FindResorceByText(Gr *KeystoreData, TextToFind string) (err error, Res []FindRes) {
	FidText := strings.TrimSpace(strings.ToLower(TextToFind))
	var RetErr error
	RsRet := make([]FindRes, 0)
	for _, GrName := range Gr.Groups {
		RsRetInG := make([]ResourceItem, 0)
		for _, ResCninG := range GrName.Resources {
			if strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.Name)), FidText) ||
				strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.Ipaddr)), FidText) ||
				strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.FQDN)), FidText) ||
				strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.Username)), FidText) ||
				strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.SNMPv3USM)), FidText) ||
				strings.Contains(strings.TrimSpace(strings.ToLower(ResCninG.Description)), FidText) {
				RsRetInG = append(RsRetInG, ResCninG)
			}
		}
		if len(RsRetInG) > 0 {
			RsRet = append(RsRet, FindRes{GrName.Groupname, RsRetInG})
		}
	}
	if len(RsRet) == 0 {
		RetErr = fmt.Errorf("Error: %s", "Resource not found")
	}
	return RetErr, RsRet
}

func main() {
	Flagname := flag.String("n", "", "Resource name")
	Flagip := flag.String("i", "", "Resource IP adress")
	Flagfqdn := flag.String("fqdn", "", "Resource FQDN adress")
	Flagusername := flag.String("u", "", "Username")
	Flagpassword := flag.String("p", "", "Password")
	Flagpassword2 := flag.String("p2", "", "Enable password")
	Description := flag.String("d", "", "Description")
	SNMPver := flag.Int("snmpver", 0, "SNMP version, 2 or 3")
	SNMPv3USM := flag.String("snmpv3u", "", "SNMP v3 user name")
	SNMPv3AuthProto := flag.String("a", "", "SNMP v3 auth protocol, must be md5, sha or none")
	SNMPv3AuthKey := flag.String("A", "", "SNMP v3 auth key")
	SNMPv3PrivProto := flag.String("x", "", "SNMP v3 priv protocol, must be des, aes or none")
	SNMPv3PrivKey := flag.String("X", "", "SNMP v3 auth key")
	SNMPv2Community := flag.String("c", "", "SNMP v2 community string")

	Flaggroupname := flag.String("g", "Default", "Group name")
	Listgroup := flag.Bool("lg", false, "List group")
	ListAll := flag.Bool("l", false, "List all")
	Flagaddresource := flag.Bool("add", false, "Add resource")
	Flageditresource := flag.Bool("edit", false, "Edit resource")
	Flagdelete := flag.Bool("delete", false, "Delete resource")
	Flagcopy := flag.String("copy", "", "Provide new name of the resource")
	Flagdeleteemptygp := flag.Bool("deletegroup", false, "Delete empty group")
	Listresourcesingroup := flag.Bool("lrg", false, "Provide group name -g for list resources in this group")
	Showresource := flag.Bool("show", false, "Provide group name -g and resource name -n")
	KeystoreName := flag.String("keystore", "Resources.json", "Name of the keystore - file name like: keystore1.json")
	MakeUnencryptedXML := flag.String("makexml", "", "Make unencrypted xml file")
	ChangeMasterPassword := flag.Bool("passwd", false, "Change Master password for datastore")
	FindResources := flag.String("find", "", "Find resources (all fields except passwords) by text, no case sensivity")
	flag.Parse()

	DoBackup := true
	UseCmdFlagNumber := 0

	ex, err := os.Executable()
	if err != nil {
		panic(any(err))
	}

	//Проверка комманд
	if len(*FindResources) > 0 {
		UseCmdFlagNumber++
	}
	if *Showresource {
		if len(*Flagname) == 0 {
			fmt.Println("You must provide resource name")
			os.Exit(1)
		} else {
			if len(*Flagname) < 3 {
				fmt.Println("Name length must be at least 3 characters long")
				os.Exit(1)
			}
		}
		UseCmdFlagNumber++
	}
	if *Flagaddresource {
		if len(*Flagname) == 0 {
			fmt.Println("You must provide resource name")
			os.Exit(1)
		} else {
			if len(*Flagname) < 3 {
				fmt.Println("Name length must be at least 3 characters long")
				os.Exit(1)
			}
		}
		UseCmdFlagNumber++
	}
	if *Flagdelete {
		if len(*Flagname) == 0 {
			fmt.Println("You must provide resource name")
			os.Exit(1)
		} else {
			if len(*Flagname) < 3 {
				fmt.Println("Name length must be at least 3 characters long")
				os.Exit(1)
			}
		}
		UseCmdFlagNumber++
	}
	if *Listgroup {
		UseCmdFlagNumber++
	}
	if *Listresourcesingroup {
		UseCmdFlagNumber++
	}
	if *ListAll {
		UseCmdFlagNumber++
	}
	if len(*Flagcopy) > 0 {
		if len(*Flagcopy) < 3 {
			fmt.Println("Name length of the source resource must be at least 3 characters long")
			os.Exit(1)
		}
		if len(*Flagname) == 0 {
			fmt.Println("You must provide resource name")
			os.Exit(1)
		} else {
			if len(*Flagname) < 3 {
				fmt.Println("Name length must be at least 3 characters long")
				os.Exit(1)
			}
		}
		UseCmdFlagNumber++
	}
	if *Flageditresource {
		if len(*Flagname) == 0 {
			fmt.Println("You must provide resource name")
			os.Exit(1)
		} else {
			if len(*Flagname) < 3 {
				fmt.Println("Name length must be at least 3 characters long")
				os.Exit(1)
			}
		}
		UseCmdFlagNumber++
	}

	if *Flagdeleteemptygp {
		if len(*Flaggroupname) == 0 {
			fmt.Println("You must provide group name (group must be empty)")
			os.Exit(1)
		}
		UseCmdFlagNumber++
	}

	if *ChangeMasterPassword {
		UseCmdFlagNumber++
	}

	if len(*MakeUnencryptedXML) > 0 {
		UseCmdFlagNumber++
	}

	if UseCmdFlagNumber == 0 {
		fmt.Println("You need to provide command flag (-add -show, -delete, -edit, -deletegroup, -l, -lg, -lrg, -find, -copy, -passwd or -makexml)")
		os.Exit(1)
	}
	if UseCmdFlagNumber > 1 {
		fmt.Println("You can provide only one command flag  in single operation")
		os.Exit(1)
	}

	exPath := filepath.Dir(ex)
	pathseparator := "/"
	if runtime.GOOS == "windows" {
		pathseparator = "\\"
	}
	jsonSettingsFile, jsonSettingsFileErr := os.Open(exPath + pathseparator + "settings.json")
	if jsonSettingsFileErr != nil {
		fmt.Println(jsonSettingsFileErr)
	}
	defer jsonSettingsFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonSettingsFile)
	var SettingDada Settings
	umErr := json.Unmarshal(byteValue, &SettingDada)
	if umErr == nil {
		*KeystoreName = SettingDada.Default_keystore
		if SettingDada.Create_backups == 0 {
			fmt.Println("Warning! backup is disabled")
			DoBackup = false
		}
	}

	fmt.Println("Keystore will be:", *KeystoreName)

	KeystorePassword := ""

	fmt.Print("Password:\r\n")

	KeystorePasswordByte, pEerr := terminal.ReadPassword(int(syscall.Stdin))
	if pEerr != nil {
		fmt.Println(pEerr)
		os.Exit(1)
	} else {
		KeystorePassword = string(KeystorePasswordByte)
	}

	Er, Gr := checkFile(*KeystoreName, KeystorePassword, DoBackup)
	if Er != nil {
		fmt.Println(Er)
	}

	if len(*FindResources) >= 2 {
		MessageToCons := fmt.Sprintf("Find resource by text \"%s\"in all field except password, no case sensivity", *FindResources)
		fmt.Println(MessageToCons)
		Ferr, Fres := FindResorceByText(Gr, *FindResources)
		if Ferr != nil {
			fmt.Println(Ferr)
			os.Exit(1)
		}
		for _, FResCurrent := range Fres {
			fmt.Println("======================================================================")
			fmt.Println("Resources int group:", FResCurrent.Groupname)
			for _, FresInTheGroupCurrent := range FResCurrent.ResourcesInTheGroup {
				fmt.Println("----------------------------------------------------------------------")
				ShowRes(FresInTheGroupCurrent, KeystorePassword)
			}
		}
		os.Exit(0)
	}

	if *ChangeMasterPassword {
		KeystoreNewPassword := ""

		fmt.Print("New password:\r\n")

		KeystorePasswordByte, pEerr := terminal.ReadPassword(int(syscall.Stdin))
		if pEerr != nil {
			fmt.Println(pEerr)
			os.Exit(1)
		} else {
			KeystoreNewPassword = string(KeystorePasswordByte)
		}

		Er = ChangePassword(Gr, KeystorePassword, KeystoreNewPassword)
		if pEerr != nil {
			fmt.Println(pEerr)
			os.Exit(1)
		} else {
			WriteData(*KeystoreName, Gr)
			fmt.Println("Password changed!")
			os.Exit(0)
		}
	}

	if len(*MakeUnencryptedXML) > 3 {
		Er = MakePlainetxXML(*MakeUnencryptedXML, Gr, KeystorePassword)
		if Er != nil {
			fmt.Println(Er)
		}
		os.Exit(0)
	}

	if *ListAll {
		fmt.Println("List groups and resources")
		fmt.Println("-------------------------")
		LastGroupIndex := len((Gr).Groups) - 1
		for CurrentGroupIndex, CurrentGroup := range (*Gr).Groups {
			fmt.Println("|--", CurrentGroup.Groupname)
			for _, CurrentResourceInGroup := range CurrentGroup.Resources {
				if CurrentGroupIndex == LastGroupIndex {
					fmt.Println("   |--", CurrentResourceInGroup.Name)
				} else {
					fmt.Println("|  |--", CurrentResourceInGroup.Name)
				}

			}
		}
		os.Exit(0)
	}

	if *Listgroup {
		for _, CurrentGroup := range (*Gr).Groups {
			fmt.Println(CurrentGroup.Groupname)
		}
		os.Exit(0)
	}

	if *Listresourcesingroup {
		fmt.Println("Find resources in group", *Flaggroupname)
		for _, CurrentGroup := range (*Gr).Groups {
			if CurrentGroup.Groupname == *Flaggroupname {
				for _, CurrentResourceInGroup := range CurrentGroup.Resources {
					fmt.Println(CurrentResourceInGroup.Name)
				}
			}

		}
		os.Exit(0)
	}

	if *Showresource {
		if CheckFlag("n") {
			ResourcenameFound := false
			GroupnameFound := false
			for _, CurrentGroup := range (*Gr).Groups {
				if CurrentGroup.Groupname == *Flaggroupname {
					GroupnameFound = true
					for _, CurrentResourceInGroup := range CurrentGroup.Resources {
						if CurrentResourceInGroup.Name == *Flagname {
							ResourcenameFound = true
							ShowRes(CurrentResourceInGroup, KeystorePassword)
						}
					}
				}
			}
			if !GroupnameFound {
				fmt.Println("Group not found")
			}
			if !ResourcenameFound {
				fmt.Println("Resource not found")
			}
		} else {
			fmt.Println("Please provide resource name")
		}

		os.Exit(0)
	}

	if *Flagaddresource {
		if CheckFlag("n") {
			AddErr := AddData(*Flaggroupname,
				*Flagname,
				*Flagip,
				*Flagfqdn,
				*Flagusername,
				*Flagpassword,
				*Flagpassword2,
				*SNMPver,
				*SNMPv3USM,
				*SNMPv3AuthProto,
				*SNMPv3AuthKey,
				*SNMPv3PrivProto,
				*SNMPv3PrivKey,
				*SNMPv2Community,
				*Description,
				Gr,
				KeystorePassword)
			if AddErr != nil {
				fmt.Println(AddErr)
				os.Exit(1)
			} else {
				fmt.Println("Resource added")
			}
			WriteData(*KeystoreName, Gr)
		} else {
			fmt.Println("Please provide resource data")
		}

		os.Exit(0)
	}

	if *Flagdelete {
		if CheckFlag("n") {
			DeleteErr := DeleteResource(*Flagname, *Flaggroupname, Gr)
			if DeleteErr != nil {
				fmt.Println(DeleteErr)
				os.Exit(1)
			} else {
				fmt.Println("Resource deleted")
			}
			WriteData(*KeystoreName, Gr)
		} else {
			fmt.Println("Please provide resource name")
		}
		os.Exit(0)
	}

	if *Flagdeleteemptygp {
		DeleteErr := DeleteEmptyGroup(*Flaggroupname, Gr)
		if DeleteErr != nil {
			fmt.Println(DeleteErr)
			os.Exit(1)
		} else {
			fmt.Println("Group deleted")
		}
		WriteData(*KeystoreName, Gr)

		os.Exit(0)
	}

	if *Flageditresource {
		if CheckFlag("n") {
			DeleteErr := EditResource(*Flaggroupname,
				*Flagname,
				*Flagip,
				*Flagfqdn,
				*Flagusername,
				*Flagpassword,
				*Flagpassword2,
				*SNMPver,
				*SNMPv3USM,
				*SNMPv3AuthProto,
				*SNMPv3AuthKey,
				*SNMPv3PrivProto,
				*SNMPv3PrivKey,
				*SNMPv2Community,
				*Description,
				Gr,
				KeystorePassword)
			if DeleteErr != nil {
				fmt.Println(DeleteErr)
				os.Exit(1)
			} else {
				fmt.Println("Edit resource complete")
			}
			WriteData(*KeystoreName, Gr)
		} else {
			fmt.Println("Please provide resource name")
		}

		os.Exit(0)
	}
	if len(*Flagcopy) > 0 {
		if CheckFlag("n") {
			CopyErr := CopyResource(*Flaggroupname,
				*Flagname,
				*Flagip,
				*Flagfqdn,
				*Flagusername,
				*Flagpassword,
				*Flagpassword2,
				*SNMPver,
				*SNMPv3USM,
				*SNMPv3AuthProto,
				*SNMPv3AuthKey,
				*SNMPv3PrivProto,
				*SNMPv3PrivKey,
				*SNMPv2Community,
				*Description,
				Gr,
				KeystorePassword,
				*Flagcopy)
			if CopyErr != nil {
				fmt.Println(CopyErr)
				os.Exit(1)
			} else {
				fmt.Println("Copy resource complete")
			}
			WriteData(*KeystoreName, Gr)
		} else {
			fmt.Println("Please provide resource name")
		}

		os.Exit(0)
	}
	WriteData(*KeystoreName, Gr)
}
