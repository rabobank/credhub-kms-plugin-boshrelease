package plugin

import (
	"fmt"
	pb "github.com/rabobank/credhub-kms-plugin/v1beta1"
	"golang.org/x/net/context"
	"testing"
	"time"
)

var (
	theTime, _ = time.Parse(DateFormat, "2023-11-22 10:52")
	key1       = Key{Name: "key0001", Value: "bcdefghijklmnopqrstuvwxyz1234567", Active: false, Date: KeySetTime(theTime)}
	key2       = Key{Name: "key0002", Value: "abcdefghijklmnopqrstuvwxyz123456", Active: false, Date: KeySetTime(theTime)}
	key3       = Key{Name: "key0003", Value: "this-is-a-32-byte-encryption-key", Active: true, Date: KeySetTime(theTime)}
	encKeySet  = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
)

func Test_GetString(t *testing.T) {
	result := encKeySet.String()
	expected := fmt.Sprintf(" {name:key0001, active=false, date=2023-11-22 10:52} {name:key0002, active=false, date=2023-11-22 10:52} {name:key0003, active=true, date=2023-11-22 10:52}")
	if result != expected {
		t.Errorf("string of EncryptionKeySet incorrect:\n%s  <= result \n%s   <= expected", result, expected)
	}
}

func Test_GetCurrentKeyValue(t *testing.T) {
	result := encKeySet.GetCurrentKeyValue()
	expected := fmt.Sprintf("this-is-a-32-byte-encryption-key")
	if result != expected {
		t.Errorf("GetCurrentKeyValue of EncryptionKeySet incorrect:\n%s  <= result \n%s   <= expected", result, expected)
	}
}

func Test_GetCurrentKeyNamePadded(t *testing.T) {
	result := encKeySet.GetCurrentKeyNamePadded()
	expected := fmt.Sprintf("         key0003")
	if result != expected {
		t.Errorf("GetCurrentKeyNamePadded of EncryptionKeySet incorrect:\n%s  <= result \n%s   <= expected", result, expected)
	}
}

func Test_GetValueOfKey(t *testing.T) {
	result := encKeySet.GetValueOfKey("key0002")
	expected := fmt.Sprintf("abcdefghijklmnopqrstuvwxyz123456")
	if result != expected {
		t.Errorf("GetValueOfKey of EncryptionKeySet incorrect:\n%s  <= result \n%s   <= expected", result, expected)
	}
}

func Test_validateKeySet(t *testing.T) {
	//
	// first test with a good encKeySet:
	if valErrors := validateKeySet(encKeySet); len(valErrors) != 0 {
		t.Errorf("validateKeySet failed, we expected 0 errors, but got %d", len(valErrors))
	}

	//
	// test with a duplicate key name:
	key1.Name = "key0002"
	encKeySetA := EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	var valErrors []error
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected := "duplicate key name found: key0002"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key1.Name = "key0001"

	//
	// test with a duplicate key value:
	key2.Value = "this-is-a-32-byte-encryption-key"
	encKeySetA = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	valErrors = nil
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected = "duplicate key value found for key with name: key0003"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key2.Value = "abcdefghijklmnopqrstuvwxyz123456"

	//
	// test with a key value that is not 32 bytes long:
	key2.Value = "this-is-a-33-byte-encryption-keyY"
	encKeySetA = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	valErrors = nil
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected = "key key0002 has an encryption key with length 33, it should be 32 bytes long"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key2.Value = "abcdefghijklmnopqrstuvwxyz123456"

	//
	// test with a key name that more than 16 bytes long:
	key2.Name = "this-is-a-25-char-keyname"
	encKeySetA = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	valErrors = nil
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected = "the name this-is-a-25-char-keyname is more than 16 bytes long"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key2.Name = "key0002"

	//
	// test with a multiple active keys:
	key1.Active = true
	encKeySetA = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	valErrors = nil
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected = "number of active keys should be 1, but is 2"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key1.Active = false

	//
	// test with a no active keys:
	key3.Active = false
	encKeySetA = EncryptionKeySet{Keys: []Key{key1, key2, key3}}
	valErrors = nil
	if valErrors = validateKeySet(encKeySetA); len(valErrors) != 1 {
		t.Errorf("validateKeySet failed, we expected 1 error, but got %d", len(valErrors))
	}
	expected = "number of active keys should be 1, but is 0"
	if valErrors[0].Error() != expected {
		t.Errorf("validateKeySet failed, we expected error '%s', but got '%s'", expected, valErrors[0].Error())
	}
	key3.Active = true
}

func Test_EncryptDecrypt(t *testing.T) {
	plgin := new(Plugin)
	CurrentKeySet = &encKeySet
	testData := "data to be encrypted should give a cipher length of 82"
	if encryptResponse, err := plgin.Encrypt(context.Background(), &pb.EncryptRequest{Version: "1", Plain: []byte(testData)}); err != nil {
		t.Errorf("Encrypt failed: %s", err)
	} else {
		fmt.Printf("cipher length: %d\n", len(encryptResponse.Cipher))
		expectedLength := 98
		if len(encryptResponse.Cipher) != expectedLength {
			t.Errorf("Encrypt failed: cipher length should be %d but is %d", expectedLength, len(encryptResponse.Cipher))
		}

		if decryptResponse, err := plgin.Decrypt(context.Background(), &pb.DecryptRequest{Version: "1", Cipher: encryptResponse.Cipher}); err != nil {
			t.Errorf("Decrypt failed: %s", err)
		} else {
			fmt.Printf("plain length: %d\n", len(decryptResponse.Plain))
			expectedLength = 54
			if len(decryptResponse.Plain) != expectedLength {
				t.Errorf("Decrypt failed: plain length should be %d but is %d", expectedLength, len(decryptResponse.Plain))
			}
			if string(decryptResponse.Plain) != testData {
				t.Errorf("Decrypt failed: plain should be '%s' but is '%s'", testData, decryptResponse.Plain)
			}
		}

		// we now make another key active, and try again to decrypt:
		CurrentKeySet.Keys[2].Active = false
		CurrentKeySet.Keys[0].Active = true

		if decryptResponse, err := plgin.Decrypt(context.Background(), &pb.DecryptRequest{Version: "1", Cipher: encryptResponse.Cipher}); err != nil {
			t.Errorf("Decrypt failed: %s", err)
		} else {
			fmt.Printf("plain length: %d\n", len(decryptResponse.Plain))
			expectedLength = 54
			if len(decryptResponse.Plain) != expectedLength {
				t.Errorf("Decrypt failed: plain length should be %d but is %d", expectedLength, len(decryptResponse.Plain))
			}
			if string(decryptResponse.Plain) != testData {
				t.Errorf("Decrypt failed: plain should be '%s' but is '%s'", testData, decryptResponse.Plain)
			}
		}
	}
}
