package main

import (
	"encoding/hex"
	"log"
	"os"
	"strconv"

	"github.com/gorilla/securecookie"
)

// To Generate Secrets
func main() {
	var length int
	if len(os.Args) > 1 {
		argLen, err := strconv.ParseInt(os.Args[1], 10, 64)
		if err != nil {
			log.Fatal("Invalid argument, first argument must be the secret length.\n example: go run generate_secret.go 64")
		}
		length = int(argLen / 2)
	} else {
		length = 16
	}
	randBytes := securecookie.GenerateRandomKey(length)
	secret := hex.EncodeToString((randBytes))

	log.Println(secret)
}
