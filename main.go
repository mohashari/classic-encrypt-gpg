package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// change as required
const pubKey = "public.gpg"
const private = "private.gpg"
const fileToEnc = "./folder-file/temp.txt"
const folderDecrypt = "./folder-decrypt/"
const passPhrase = "Testing123"

func main() {
	log.Println("Public key:", pubKey)

	// Read in public key
	recipient, err := readEntity(pubKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	f, err := os.Open(fileToEnc)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	fileName := strings.ReplaceAll(fileToEnc, ".txt", "")
	dst, err := os.Create(fileName + ".gpg")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dst.Close()
	fBuf := new(bytes.Buffer)
	fBuf.ReadFrom(f)
	resp, err := encrypt(recipient, nil, fBuf.Bytes())
	if _, err := dst.Write(resp); err != nil {
		log.Println(err)
	}

	//dst, err := os.Open("./folder-file/BGPO01210603.TXT.gpg")
	entityList, err := readPrivateKey(private)
	if err != nil {
		fmt.Println(err)
		return
	}

	originalName := strings.ReplaceAll(dst.Name(), "./folder-file/", "")
	originalName = strings.ReplaceAll(originalName, ".gpg", "")
	decriptedFile, err := os.Create(folderDecrypt + originalName + ".txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	// buf := new(bytes.Buffer)
	// buf.ReadFrom(dst)
	fmt.Printf("%d", resp)
	descriptFL, err := decrypt(resp, entityList)
	if err != nil {
		log.Print(err)
	}
	decriptedFile.Write(descriptFL)

}

func encrypt(recip openpgp.EntityList, signer *openpgp.Entity, r []byte) (resp []byte, err error) {
	buf := new(bytes.Buffer)
	wc, err := openpgp.Encrypt(buf, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return resp, err
	}
	if _, err := wc.Write(r); err != nil {
		return resp, err
	}
	err = wc.Close()
	if err != nil {
		return resp, err
	}
	resp, err = ioutil.ReadAll(buf)
	return resp, err
}

func readPrivateKey(name string) (openpgp.EntityList, error) {
	f, err := os.Open(name)
	if err != nil {
		log.Fatal("failed to open file. " + err.Error())
		return nil, err
	}
	defer f.Close()

	entitiList, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}

	entity := entitiList[0]
	passphraseByte := []byte(passPhrase)
	log.Println("Decrypting private key using passphrase")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	return entitiList, nil
}

func decrypt(r []byte, recip openpgp.EntityList) (resp []byte, err error) {

	md, err := openpgp.ReadMessage(bytes.NewBuffer(r), recip, nil, nil)
	if err != nil {
		log.Fatal(err)
		return resp, err
	}
	resp, err = ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return resp, err
	}
	return resp, err
}

func readEntity(name string) (openpgp.EntityList, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(f)

	if err != nil {
		return nil, err
	}
	return entityList, nil
}
