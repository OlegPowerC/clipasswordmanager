package main

import (
	"testing"
)

func TestEncryptPassword(t *testing.T) {
	var TestPlainTextPassword string
	var TestMasterKey string
	TestPlainTextPassword = "Qwerty123"
	TestMasterKey = "12345"
	TestEncryptedPassword, TestEncryptErr := EncryptPassword(TestPlainTextPassword, TestMasterKey)
	if TestEncryptErr != nil {
		t.Errorf("%s", TestEncryptErr)
	}
	DecryptedPassword, DecryptedErr := DecryptPassword(TestEncryptedPassword, TestMasterKey)
	if DecryptedErr != nil {
		t.Errorf("%s", DecryptedErr)
	}

	if TestPlainTextPassword != DecryptedPassword {
		t.Errorf("Encrypt - Decrypt not simmetrical")
	}
}
