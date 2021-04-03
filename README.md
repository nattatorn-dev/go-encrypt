# Encryption

## Run

```bash
$ go run main.go
message : Hello Encrypt
key to encrypt/decrypt : 1515863118d20582f989cf8280151b1cf1a2520b38bf89134701c4c4d3e5712d
encrypted : 68d106a9538fa0a760824aa0df0a47fe5c8f57d49c53c9873c23e92126c5d61c2e72f4a7e7c71e1c7c
decrypted : Hello Encrypt
```

## Testing

```bash
$ go test
```

## Benchmark
BenchmarkEncrypt/Hello                   1205151              1001 ns/op            1136 B/op         11 allocs/op

- 1205151 is the number of iterations for i := 0; i < b.N; i++
- 1001 ns/op is approximate time it took for one iteration to complete
- 1136 B/op allocs/op means how many distinct memory allocations - occurred per op (single iteration).
- 11 allocs/op B/op is how many bytes were allocated per op.

```bash
$ go test -bench=. -benchtime=20s -benchmem
BenchmarkEncrypt/Hello                   1205151              1001 ns/op            1136 B/op         11 allocs/op
BenchmarkEncrypt/Hello-2                 1292458               936.5 ns/op          1136 B/op         11 allocs/op
BenchmarkEncrypt/Hello-4                 1281004               939.6 ns/op          1136 B/op         11 allocs/op
BenchmarkEncrypt/Hello-8                 1309190               956.1 ns/op          1136 B/op         11 allocs/op

```

## Explain

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func main() {

	bytes := make([]byte, 32) //generate a random 32 byte key for AES-256
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	message := "Hello Encrypt"
	fmt.Printf("message : %s\n", message) //encode key in bytes to string and keep as secret, put in a vault
	fmt.Printf("key to encrypt/decrypt : %s\n", key)

	encrypted := encrypt(message, key)
  fmt.Printf("encrypted : %s\n", encrypted)

	decrypted := decrypt(encrypted, key)
	fmt.Printf("decrypted : %s\n", decrypted)
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {
	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
```
