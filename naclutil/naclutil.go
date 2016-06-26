// Package naclutil contains utility functions for working with NaCL key pairs.
package naclutil

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	iou "io/ioutil"
	"os"

	box "golang.org/x/crypto/nacl/box"
)

const (
	NonceLength = 24
	KeyLength   = 32
)

// Read the contents of a file
func IngestFile(path string) ([]byte, error) {
	b, err := iou.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Encode binary (potentially non-printable) data as a Base64-encoded string.
func EncodeBytes(bin []byte) bytes.Buffer {
	var buf bytes.Buffer
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	enc.Write(bin)
	enc.Close()
	return buf
}

// Create directory where keys will be stored.
func CreateKeyStore(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		fmt.Printf("DEBUG: creating key store [%s]\n", path)
		err = os.MkdirAll(path, 0700)
		if err != nil {
			return err
		}
		fi, err = os.Stat(path)
		if err != nil {
			return err
		}
	}
	if fi == nil {
		return err
	}
	if !fi.IsDir() {
		return err
	}
	return nil
}

// Return keys at the specified location, generating and creating them if necessary.
func FetchKeypair(path, name string) ([]byte, []byte, error) {
	err := CreateKeyStore(path)
	if err != nil {
		return nil, nil, err
	}

	pubPath := fmt.Sprintf("%s/%s.pub", path, name)
	pubInfo, err := os.Stat(pubPath)
	pubExists := true
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, err
		}
		pubExists = false
	}

	keyPath := fmt.Sprintf("%s/%s.key", path, name)
	keyInfo, err := os.Stat(keyPath)
	keyExists := true
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, err
		}
		keyExists = false
	}

	/* Unacceptable: one path exists and other does not */
	if pubExists != keyExists {
		err = fmt.Errorf("need neither or both of %s %s\n", pubPath, keyPath)
		return nil, nil, err
	}

	/* Unacceptable: either path is a directory */
	if pubExists && pubInfo.IsDir() {
		err = fmt.Errorf("found directory at %s\n", pubPath)
		return nil, nil, err
	}
	if keyExists && keyInfo.IsDir() {
		err = fmt.Errorf("found directory at %s\n", keyPath)
		return nil, nil, err
	}

	if !pubExists {
		fmt.Printf("NOTICE: generating key pair for [%s]\n", name)
		pub, key, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		fmt.Printf("NOTICE: writing public key to [%s]\n", pubPath)
		err = iou.WriteFile(pubPath, (*pub)[:], 0644)
		if err != nil {
			return nil, nil, err
		}

		fmt.Printf("NOTICE: writing private key to [%s]\n", keyPath)
		err = iou.WriteFile(keyPath, (*key)[:], 0600)
		if err != nil {
			return nil, nil, err
		}

		return (*pub)[:], (*key)[:], nil

	} else {
		fmt.Printf("NOTICE: using pre-generated keypair stored in [%s]\n", path)
		pub, err := IngestFile(pubPath)
		if err != nil {
			return nil, nil, err
		}
		key, err := IngestFile(keyPath)
		if err != nil {
			return nil, nil, err
		}

		return pub, key, nil
	}
}

func EncryptMessage(msg, _toPub, _fromKey []byte) ([]byte, []byte, error) {
	var nonce [NonceLength]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, nil, err
	}
	/* Copy byte slices into the static arrays that box.Seal expects. */
	var toPub, fromKey [KeyLength]byte
	copy(toPub[:], _toPub)
	copy(fromKey[:], _fromKey)
	enc := box.Seal(nil, msg, &nonce, &toPub, &fromKey)
	return enc, nonce[:], nil
}

func DecryptMessage(enc, _nonce, _fromPub, _toKey []byte) ([]byte, error) {
	var nonce [NonceLength]byte
	copy(nonce[:], _nonce)
	var fromPub, toKey [KeyLength]byte
	copy(fromPub[:], _fromPub)
	copy(toKey[:], _toKey)
	msg, success := box.Open(nil, enc, &nonce, &fromPub, &toKey)
	if !success {
		return nil, fmt.Errorf("failed to decrypt message")
	}
	return msg, nil
}
