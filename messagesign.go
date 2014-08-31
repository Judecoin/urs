// Copyright 2014 The Monero Developers.
// All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcec"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcutil"
)

// Flags
var gFlag = flag.String("set-generate", "", "Generates to a new keypair; g|set-generate [filename]")
var vtFlag = flag.String("verify-text", "", "Verify a text message; v|verify-text [filename]")
var vbFlag = flag.String("verify-bin", "", "Verify a binary message; b|verify-bin [filename]")
var stFlag = flag.String("sign-text", "", "Sign a binary message; s|verify-bin [filename]")
var sbFlag = flag.String("sign-bin", "", "Sign a text message; z|verify-bin [filename]")
var krFlag = flag.String("keyring", "", "Load a keyring of pubkeys; k|keyring [filename]")
var kpFlag = flag.String("keypair", "", "Load a keypair to sign from; p|keypair [filename]")
var sigFlag = flag.String("sig", "", "Load a Base58 signature to verify; S|sig [filename]")
var blindFlag = flag.Bool("blind", false, "Enable signature blinding (non-unique!); B|blind")

func init() {
	// Short version flags
	flag.StringVar(gFlag, "g", "", "Generates to a new keypair; g|set-generate [filename]")
	flag.StringVar(vtFlag, "v", "", "Verify a text message; v|verify-text [filename]")
	flag.StringVar(vbFlag, "b", "", "Verify a binary message; b|verify-bin [filename]")
	flag.StringVar(stFlag, "s", "", "Sign a text message; s|verify-bin [filename]")
	flag.StringVar(sbFlag, "z", "", "Sign a binary message; z|verify-bin [filename]")
	flag.StringVar(krFlag, "k", "", "Load a keyring of pubkeys; k|keyring [filename]")
	flag.StringVar(kpFlag, "p", "", "Load a keypair to sign from; p|keypair [filename]")
	flag.StringVar(sigFlag, "S", "", "Load a Base58 signature to verify; S|sig [filename]")
	flag.BoolVar(blindFlag, "B", false, "Enable signature blinding (non-unique!); B|blind")
}

// generateKeyPair generates and stores an ECDSA keypair to a file.
func generateKeyPair(filename string) error {
	// Generate keypairs.
	aKeypair, err := ecdsa.GenerateKey(btcec.S256(), crand.Reader)
	if err != nil {
		return err
	}
	pubkeyBtcec := btcec.PublicKey{aKeypair.PublicKey.Curve,
		aKeypair.PublicKey.X,
		aKeypair.PublicKey.Y}
	keypairBtcec := btcec.PrivateKey{aKeypair.PublicKey, aKeypair.D}

	// Create a map to json marshal
	keypairMap := make(map[string]string)
	keypairMap["pubkey"] = hex.EncodeToString(pubkeyBtcec.SerializeCompressed())
	keypairMap["privkey"] = hex.EncodeToString(keypairBtcec.Serialize())

	// Store the address in case anyone wants to use it for BTC
	pkh, err := btcutil.NewAddressPubKey(pubkeyBtcec.SerializeCompressed(),
		&btcnet.MainNetParams)
	if err != nil {
		return err
	}
	keypairMap["address"] = pkh.EncodeAddress()

	b, err := json.Marshal(keypairMap)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, b, 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()

	// set-generate
	if *gFlag != "" {
		err := generateKeyPair(*gFlag)
		if err != nil {
			fmt.Printf("Keypair generation failed; error: %v\n", err)
			return
		}
		fmt.Println("Keypair generated successfully.")
		return
	}

	// verify a text file
	if *vtFlag != "" && !*blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: verify text called but no keyring file given.")
			return
		}
		if *sigFlag == "" {
			fmt.Println("Error: verify text called but no signature file given.")
			return
		}

		m, err := GetTextFileData(*vtFlag)
		if err != nil {
			fmt.Printf("Text verification failed on message load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, nil)
		if err != nil {
			fmt.Printf("Text verification failed on keyring load; error: %v\n", err)
			return
		}

		sig, err := GetSigFileData(*sigFlag)
		if err != nil {
			fmt.Printf("Text verification failed on sig load; error: %v\n", err)
			return
		}

		decodedSig := &RingSign{nil, nil, nil, nil}

		err = decodedSig.FromBase58(string(sig))
		if err != nil {
			fmt.Printf("Text verification failed on sig parse; error: %v\n", err)
			return
		}

		isValid := Verify(kr, m, decodedSig)

		fmt.Printf("%v\n", isValid)

		return
	}

	// verify a binary file
	if *vbFlag != "" && !*blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: verify bin called but no keyring file given.")
			return
		}
		if *sigFlag == "" {
			fmt.Println("Error: verify bin called but no signature file given.")
			return
		}

		m, err := GetBinaryFileData(*vbFlag)
		if err != nil {
			fmt.Printf("Bin verification failed on message load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, nil)
		if err != nil {
			fmt.Printf("Bin verification failed on keyring load; error: %v\n", err)
			return
		}

		sig, err := GetSigFileData(*sigFlag)
		if err != nil {
			fmt.Printf("Bin verification failed on sig load; error: %v\n", err)
			return
		}

		decodedSig := &RingSign{nil, nil, nil, nil}

		err = decodedSig.FromBase58(string(sig))
		if err != nil {
			fmt.Printf("Bin verification failed on sig parse; error: %v\n", err)
			return
		}

		isValid := Verify(kr, m, decodedSig)

		fmt.Printf("%v\n", isValid)

		return
	}

	// sign a text file
	if *stFlag != "" && !*blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: sign text called but no keyring file given.")
			return
		}
		if *kpFlag == "" {
			fmt.Println("Error: sign text called but no keypair file given.")
			return
		}

		m, err := GetTextFileData(*stFlag)
		if err != nil {
			fmt.Printf("Text signing failed on message load; error: %v\n", err)
			return
		}

		kp, err := ReadKeyPair(*kpFlag)
		if err != nil {
			fmt.Printf("Text signing failed on keypair load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, kp)
		if err != nil {
			fmt.Printf("Text signing failed on keyring load; error: %v\n", err)
			return
		}

		ringsig, err := Sign(crand.Reader, kp, kr, m)
		if err != nil {
			fmt.Printf("Text signing failed on sig generation; error: %v\n", err)
			return
		}

		if Verify(kr, m, ringsig) {
			fmt.Printf("%v\n", ringsig.ToBase58())
		} else {
			fmt.Printf("Signature generated but failed to validate.\n")
		}

		return
	}

	// sign a binary file
	if *sbFlag != "" && !*blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: sign bin called but no keyring file given.")
			return
		}
		if *kpFlag == "" {
			fmt.Println("Error: sign bin called but no keypair file given.")
			return
		}

		m, err := GetBinaryFileData(*sbFlag)
		if err != nil {
			fmt.Printf("Bin signing failed on message load; error: %v\n", err)
			return
		}

		kp, err := ReadKeyPair(*kpFlag)
		if err != nil {
			fmt.Printf("Bin signing failed on keypair load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, kp)
		if err != nil {
			fmt.Printf("Bin signing failed on keyring load; error: %v\n", err)
			return
		}

		ringsig, err := Sign(crand.Reader, kp, kr, m)
		if err != nil {
			fmt.Printf("Bin signing failed on sig generation; error: %v\n", err)
			return
		}

		if Verify(kr, m, ringsig) {
			fmt.Printf("%v\n", ringsig.ToBase58())
		} else {
			fmt.Printf("Signature generated but failed to validate.\n")
		}

		return
	}

	// blind verify a text file
	if *vtFlag != "" && *blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: verify text called but no keyring file given.")
			return
		}
		if *sigFlag == "" {
			fmt.Println("Error: verify text called but no signature file given.")
			return
		}

		m, err := GetTextFileData(*vtFlag)
		if err != nil {
			fmt.Printf("Text verification failed on message load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, nil)
		if err != nil {
			fmt.Printf("Text verification failed on keyring load; error: %v\n", err)
			return
		}

		sig, err := GetSigFileData(*sigFlag)
		if err != nil {
			fmt.Printf("Text verification failed on sig load; error: %v\n", err)
			return
		}

		decodedSig := &BlindRingSign{nil, nil, nil, nil, nil, nil, nil, nil}

		err = decodedSig.FromBase58(string(sig))
		if err != nil {
			fmt.Printf("Text verification failed on sig parse; error: %v\n", err)
			return
		}

		isValid := BlindVerify(kr, m, decodedSig)

		fmt.Printf("%v\n", isValid)

		return
	}

	// blind verify a binary file
	if *vbFlag != "" && *blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: verify bin called but no keyring file given.")
			return
		}
		if *sigFlag == "" {
			fmt.Println("Error: verify bin called but no signature file given.")
			return
		}

		m, err := GetBinaryFileData(*vbFlag)
		if err != nil {
			fmt.Printf("Bin verification failed on message load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, nil)
		if err != nil {
			fmt.Printf("Bin verification failed on keyring load; error: %v\n", err)
			return
		}

		sig, err := GetSigFileData(*sigFlag)
		if err != nil {
			fmt.Printf("Bin verification failed on sig load; error: %v\n", err)
			return
		}

		decodedSig := &BlindRingSign{nil, nil, nil, nil, nil, nil, nil, nil}

		err = decodedSig.FromBase58(string(sig))
		if err != nil {
			fmt.Printf("Bin verification failed on sig parse; error: %v\n", err)
			return
		}

		isValid := BlindVerify(kr, m, decodedSig)

		fmt.Printf("%v\n", isValid)

		return
	}

	// blind sign a text file
	if *stFlag != "" && *blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: sign text called but no keyring file given.")
			return
		}
		if *kpFlag == "" {
			fmt.Println("Error: sign text called but no keypair file given.")
			return
		}

		m, err := GetTextFileData(*stFlag)
		if err != nil {
			fmt.Printf("Text signing failed on message load; error: %v\n", err)
			return
		}

		kp, err := ReadKeyPair(*kpFlag)
		if err != nil {
			fmt.Printf("Text signing failed on keypair load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, kp)
		if err != nil {
			fmt.Printf("Text signing failed on keyring load; error: %v\n", err)
			return
		}

		ringsig, err := BlindSign(crand.Reader, kp, kr, m)
		if err != nil {
			fmt.Printf("Text signing failed on sig generation; error: %v\n", err)
			return
		}

		if BlindVerify(kr, m, ringsig) {
			fmt.Printf("%v\n", ringsig.ToBase58())
		} else {
			fmt.Printf("Signature generated but failed to validate.\n")
		}

		return
	}

	// blind sign a binary file
	if *sbFlag != "" && *blindFlag {
		if *krFlag == "" {
			fmt.Println("Error: sign bin called but no keyring file given.")
			return
		}
		if *kpFlag == "" {
			fmt.Println("Error: sign bin called but no keypair file given.")
			return
		}

		m, err := GetBinaryFileData(*sbFlag)
		if err != nil {
			fmt.Printf("Bin signing failed on message load; error: %v\n", err)
			return
		}

		kp, err := ReadKeyPair(*kpFlag)
		if err != nil {
			fmt.Printf("Bin signing failed on keypair load; error: %v\n", err)
			return
		}

		kr, err := ReadKeyRing(*krFlag, kp)
		if err != nil {
			fmt.Printf("Bin signing failed on keyring load; error: %v\n", err)
			return
		}

		ringsig, err := BlindSign(crand.Reader, kp, kr, m)
		if err != nil {
			fmt.Printf("Bin signing failed on sig generation; error: %v\n", err)
			return
		}

		if BlindVerify(kr, m, ringsig) {
			fmt.Printf("%v\n", ringsig.ToBase58())
		} else {
			fmt.Printf("Signature generated but failed to validate.\n")
		}

		return
	}

	fmt.Println("Use 'urs -h' for help.")
	fmt.Println("Signature example:")
	fmt.Println("urs -sign-bin urs -keypair pair.key -keyring pubkeyring.keys")
	fmt.Println("Verify example:")
	fmt.Println("urs -verify-bin urs -sig signature -keyring pubkeyring.keys")
}
