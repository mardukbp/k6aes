package k6aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"github.com/andreburgaud/crypt2go/ecb"
	"encoding/base64"
    "encoding/binary"
    "github.com/mardukbp/padding"
)

type K6aes struct{}

func New() *K6aes {
	return &K6aes {}
}

func (c *K6aes) Encrypt (ctx context.Context, 
                         keyb64 string,
                         ssc int, 
                         plaintext string) string {

    blockSize := 16
    key, _ := base64.StdEncoding.DecodeString(keyb64)
    sscBytes := make([]byte, blockSize)
    binary.BigEndian.PutUint32(sscBytes, uint32(ssc))

    aesCipher, _ := aes.NewCipher(key)
    aesEcb := ecb.NewECBEncrypter(aesCipher)
	iv := make([]byte, blockSize)
	aesEcb.CryptBlocks(iv, sscBytes)
	aesCbc := cipher.NewCBCEncrypter(aesCipher, iv)
	padded := padding.PadIso7816([]byte(plaintext), blockSize)
	encrypted := make([]byte, len(padded))
	aesCbc.CryptBlocks(encrypted, padded)
	
	return base64.StdEncoding.EncodeToString(encrypted)
}

func (c *K6aes) Decrypt (ctx context.Context, 
                         keyb64 string,
                         ssc int, 
                         plaintext string) string {

    blockSize := 16
    key, _ := base64.StdEncoding.DecodeString(keyb64)
    sscBytes := make([]byte, blockSize)
    binary.BigEndian.PutUint32(sscBytes, uint32(ssc))
	data := []byte(plaintext)

    aesCipher, _ := aes.NewCipher(key)
    aesEcb := ecb.NewECBEncrypter(aesCipher)
	iv := make([]byte, blockSize)
	aesEcb.CryptBlocks(iv, sscBytes)
	aesCbc := cipher.NewCBCDecrypter(aesCipher, iv)
	decrypted := make([]byte, len(data))
	aesCbc.CryptBlocks(decrypted, data)
	unpadded, err := padding.UnpadIso7816(decrypted, blockSize)
	if err != nil {
		return err.Error()
	}
	return base64.StdEncoding.EncodeToString(unpadded)
}
