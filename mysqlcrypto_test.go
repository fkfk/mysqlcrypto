package mysqlcrypto

import (
	"encoding/hex"
	"testing"
)

func TestAESEncrypt(t *testing.T) {
	expected, _ := hex.DecodeString("3bb9131c101e0788dcf27e68336ae327")
	encrypted := AESEncrypt([]byte("foobar"), []byte("testcryptkey"))
	if string(encrypted) != string(expected) {
		t.Errorf("AESEncrypt mismatch(%x:%x)", encrypted, expected)
	}

	expected, _ = hex.DecodeString("e5dc9002f2f09d88b85356d93ee9f1f9fdde4874face19e7cda4af28a796a38a")
	encrypted = AESEncrypt([]byte("日本語文字列"), []byte("testcryptkey"))
	if string(encrypted) != string(expected) {
		t.Errorf("AESEncrypt(Japanese character) mismatch(%x:%x)", encrypted, expected)
	}

	expected, _ = hex.DecodeString("59A597C079C4A25CB8BA415A74204020")
	encrypted = AESEncrypt([]byte(""), []byte("testcryptkey"))
	if string(encrypted) != string(expected) {
		t.Errorf("AESEncrypt(empty value) mismatch(%x:%x)", encrypted, expected)
	}
}

func TestAESDecrypt(t *testing.T) {
	expected := "foobar"
	encrypted, _ := hex.DecodeString("3bb9131c101e0788dcf27e68336ae327")
	decrypted := AESDecrypt(encrypted, []byte("testcryptkey"))
	if string(decrypted) != expected {
		t.Errorf("AESDecrypt mismatch(%x:%x)", string(decrypted), expected)
	}

	expected = "日本語文字列"
	encrypted, _ = hex.DecodeString("e5dc9002f2f09d88b85356d93ee9f1f9fdde4874face19e7cda4af28a796a38a")
	decrypted = AESDecrypt(encrypted, []byte("testcryptkey"))
	if string(decrypted) != expected {
		t.Errorf("AESDecrypt(Japanese character) mismatch(%x:%x)", string(decrypted), expected)
	}

	expected = ""
	encrypted, _ = hex.DecodeString("59A597C079C4A25CB8BA415A74204020")
	decrypted = AESDecrypt(encrypted, []byte("testcryptkey"))
	if string(decrypted) != expected {
		t.Errorf("AESDecrypt(empty value) mismatch(%x:%x)", string(decrypted), expected)
	}
}
