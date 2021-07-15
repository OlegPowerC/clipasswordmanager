package main

import (
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	CheckIpAddrs "github.com/OlegPowerC/validate_ipaddresses"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"passstore"
	"syscall"
)

type KeystoreData struct {
	Encryptedpasswords bool    `json:"encryptedpasswords" xml:"encryptedpasswords"`
	Magicphrase        string  `json:"magicphrase" xml:"magicphrase"`
	Groups             []Group `json:"groups"`
}

type ResourceItem struct {
	Ipaddr    string `json:"ipaddr" xml:"ipaddr"`
	Name      string `json:"name" xml:"name"`
	FQDN      string `json:"fqdn" xml:"fqdn"`
	Username  string `json:"username" xml:"username"`
	Password  string `json:"password" xml:"password"`
	Password2 string `json:"password_2" xml:"password_2"`
}

type Group struct {
	Groupname string         `json:"groupname" xml:"groupname"`
	Resources []ResourceItem `json:"resources" xml:"resources"`
}

func AddData(GroupName string, Name string, Ip string, Fqdn string, Username string, Password string, Password2 string, KSData *KeystoreData, keystorepassword string) error {
	EncryptedPassword1, _ := EncryptPassword(Password, keystorepassword)
	EncryptedPassword2, _ := EncryptPassword(Password2, keystorepassword)

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
	ResourceItemNewData.Password2 = EncryptedPassword2
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

func EditResource(GroupName string, Name string, Ip string, Fqdn string, Username string, Password string, Password2 string, KSdata *KeystoreData, keystorepassword string) error {
	EncryptedPassword1, _ := EncryptPassword(Password, keystorepassword)
	EncryptedPassword2, _ := EncryptPassword(Password2, keystorepassword)

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
		if len(Fqdn) > 3 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].FQDN = Fqdn
		}
		if len(Username) > 3 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Username = Username
		}
		if len(Password) > 3 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Password = EncryptedPassword1
		}
		if len(Password2) > 3 {
			(*KSdata).Groups[FGindFinded].Resources[FRindFinded].Password2 = EncryptedPassword2
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
			}
			//если элемент последний то укоротим справа
			if FRindFinded == len((*KSdata).Groups[FGindFinded].Resources)-1 {
				(*KSdata).Groups[FGindFinded].Resources = (*KSdata).Groups[FGindFinded].Resources[:FRindFinded]
			}

			if FRindFinded > 0 && FRindFinded < len((*KSdata).Groups[FGindFinded].Resources)-1 {
				FRes := (*KSdata).Groups[FGindFinded].Resources[:FRindFinded]
				SRes := (*KSdata).Groups[FGindFinded].Resources[FRindFinded+1:]
				(*KSdata).Groups[FGindFinded].Resources = make([]ResourceItem, 0)
				(*KSdata).Groups[FGindFinded].Resources = append((*KSdata).Groups[FGindFinded].Resources, FRes...)
				(*KSdata).Groups[FGindFinded].Resources = append((*KSdata).Groups[FGindFinded].Resources, SRes...)
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
			}
			//если элемент последний то укоротим справа
			if FGindFinded == len((*KSdata).Groups)-1 {
				(*KSdata).Groups = (*KSdata).Groups[:FGindFinded]
			}

			if FGindFinded > 0 && FGindFinded < len((*KSdata).Groups)-1 {
				FGroup := (*KSdata).Groups[:FGindFinded]
				SGroup := (*KSdata).Groups[FGindFinded+1:]
				(*KSdata).Groups = make([]Group, 0)
				(*KSdata).Groups = append((*KSdata).Groups, FGroup...)
				(*KSdata).Groups = append((*KSdata).Groups, SGroup...)
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
	EncryptedPassword, EncryptErr := passstore.Encrypt(CIPHER_KEY, PlainPassword)
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
		DecryptedPassword, DecryptErr := passstore.Decrypt(CIPHER_KEY, EncryptedPassword)
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

func checkFile(filename string, keystorepassword string) (error, *KeystoreData) {
	_, err := os.Stat(filename)
	FirstGroups := make([]Group, 0)
	var FJSdata KeystoreData
	FJSdata.Groups = FirstGroups
	PasswordHash := sha1.New()
	PasswordHash.Reset()
	Hash := PasswordHash.Sum([]byte(keystorepassword))
	if os.IsNotExist(err) {
		fmt.Println("No keystore", filename, "exsist - make it")
		if len(keystorepassword) > 3 {
			FJSdata.Encryptedpasswords = true
			FJSdata.Magicphrase, _ = EncryptPassword(string(Hash), keystorepassword)
		} else {
			FJSdata.Encryptedpasswords = false
			FJSdata.Magicphrase = ""
		}
		AddData("Default", "Demoresource", "192.168.0.1", "DemoCisco.yourdomain.local", "Cisco", "Cisco", "Cisco123%", &FJSdata, keystorepassword)

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
		filebytes, err := ioutil.ReadFile(filename)
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

func main() {
	Flagname := flag.String("n", "", "Resource name")
	Flagip := flag.String("i", "", "Resource IP adress")
	Flagfqdn := flag.String("fqdn", "", "Resource FQDN adress")
	Flagusername := flag.String("u", "", "Username")
	Flagpassword := flag.String("p", "", "Password")
	Flagpassword2 := flag.String("p2", "", "Second password (for example, Cisco enable password)")
	Flaggroupname := flag.String("g", "Default", "Group name")
	Listgroup := flag.Bool("lg", false, "List group")
	Flagaddresource := flag.Bool("add", false, "Add resource")
	Flageditresource := flag.Bool("edit", false, "Edit resource")
	Flagdelete := flag.Bool("delete", false, "Delete resource")
	Flagdeleteemptygp := flag.Bool("deletegroup", false, "Delete empty group")
	Listresourcesingroup := flag.Bool("lrg", false, "Provide group name -g for list resources in this group")
	Showresource := flag.Bool("show", false, "Provide group name -g and resource name -n")
	KeystoreName := flag.String("keystore", "Resources.json", "Name of the keystore - file name like: keystore1.json")
	flag.Parse()

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

	Er, Gr := checkFile(*KeystoreName, KeystorePassword)
	if Er != nil {
		fmt.Println(Er)
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
							fmt.Println("Name      :\t\t", CurrentResourceInGroup.Name)
							fmt.Println("IP address:\t\t", CurrentResourceInGroup.Ipaddr)
							fmt.Println("FQDN      :\t\t", CurrentResourceInGroup.FQDN)
							fmt.Println("Username  :\t\t", CurrentResourceInGroup.Username)
							PlainPassword, _ := DecryptPassword(CurrentResourceInGroup.Password, KeystorePassword)
							fmt.Println("Password  :\t\t", PlainPassword)
							PlainPassword2, _ := DecryptPassword(CurrentResourceInGroup.Password2, KeystorePassword)
							fmt.Println("Second password  :\t", PlainPassword2)
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
			AddErr := AddData(*Flaggroupname, *Flagname, *Flagip, *Flagfqdn, *Flagusername, *Flagpassword, *Flagpassword2, Gr, KeystorePassword)
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
			DeleteErr := EditResource(*Flaggroupname, *Flagname, *Flagip, *Flagfqdn, *Flagusername, *Flagpassword, *Flagpassword2, Gr, KeystorePassword)
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
	WriteData(*KeystoreName, Gr)
}
