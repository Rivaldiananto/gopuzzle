package main

/*
To use this program you should remove two "condition" lines in a file $GOROOT/src/crypto/aes/cipher_asm.go:
	--- if !supportsAES {
          return newCipherGeneric(key)
	--- }

and change "case" line in a file $GOROOT/src/crypto/aes/cipher.go:

	func NewCipher(key []byte) (cipher.Block, error) {
	...
	--- case 16, 24, 32:
	+++ case 16, 24, 32, 128:
	...
	}

*/

import (
	"fmt"
	"encoding/hex"
	"crypto/sha512"
	"os"
	"hash"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"	
	"bufio"
 )

var pz_salt []byte
var pz_cipherBytes []byte
var pz_cipherBytesLen int



    // PZL3 msg
const msg = "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";


func TiamatDecodeCheck(hasher hash.Hash, pass string) string {
	r := sha512.Sum512([]byte(pass))
	
	for in := 0; in < 11512; in++ {
	r = sha512.Sum512(r[:])
	}
	pwd := make([]byte, hex.EncodedLen(64))
	hex.Encode(pwd, r[:])
	derivedKeyBytes := []byte{}
	bx := []byte{}
	for len(derivedKeyBytes) < 144 {
		if len(bx) > 0 {
			hasher.Write(bx)
		}
		hasher.Write(pwd)
		hasher.Write(pz_salt)
		bx = hasher.Sum(nil)
		hasher.Reset()

		for i := 1; i < 10000; i++ {
			hasher.Write(bx)
			bx = hasher.Sum(nil)
			hasher.Reset()
		}
		derivedKeyBytes = append(derivedKeyBytes, bx...)
	}
	block, err := aes.NewCipher(derivedKeyBytes[:128])
	if err != nil {
		panic(err)
	}
	var cp []byte = make([]byte, pz_cipherBytesLen)
	copy(cp, pz_cipherBytes)
	mode := cipher.NewCBCDecrypter(block, derivedKeyBytes[128:])
	mode.CryptBlocks(cp, cp)
	length := len(cp)
	unpadding := int(cp[length-1])
	endp := string(cp[:(length - unpadding)])

	const search = "\"kty\":\"RSA\""

	if x := strings.Contains(endp, search); x == true {
            return "1"
	} else {
	    return "0"
	}
}

func b64toBinary() {
	data, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
	panic(errors.New("base64 invalid"))
	}
	if string(data[:8]) != "Salted__" {
		panic(errors.New("Invalid data"))
	}
	pz_salt = data[8:16]
	pz_cipherBytes = data[16:]
	pz_cipherBytesLen = len(pz_cipherBytes)
}

func main() {
    b64toBinary()
    h := md5.New()

    scanner := bufio.NewScanner(os.Stdin)
    var result string
    for scanner.Scan() {
        arg := scanner.Text()
        result += TiamatDecodeCheck(h,arg)
    }

    fmt.Println(result)

}
