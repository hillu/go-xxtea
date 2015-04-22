package xxtea

import (
	"testing"
	"encoding/hex"
)

func TestEncrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	cipher, err := NewCipher(key)
	t.Log("cipher: %+v", cipher)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	crypted := make([]byte, len(plain))
	cipher.Encrypt(crypted, plain)
	t.Log(hex.Dump(crypted))
	if string(crypted) != "\x01\xdf\xae\x78\x16\xba\x47\x35\x9d\x9a\xc3\x5e\x1f\xab\x71\xb8\x3d\xcf\x3a\xc8\x8c\x9d\xdc\x4a\x10\xc6\x73\xdb\x9e\xb9\x9c\xa8" {
		t.Error("Did not get expected string after encryption")
	}
	cipher.Decrypt(plain, crypted)
	t.Log(hex.Dump(plain))
	if string(plain) != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Error("Did not get original string back after encryption/decryption")
	}
}
