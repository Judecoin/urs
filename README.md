Unique Ring Signatures (URS)
============================

[URS](http://csiflabs.cs.ucdavis.edu/~hbzhang/romring.pdf) can be used to sign plaintext or binaries anonymously 
(among a group of known users). That is a user can sign a 
message, hiding among a group of known/registered users, 
that prevents the verifier from revealing the signer's 
identity other than knowing that it is in the set of 
registered users. The size of the set of registered users 
is flexible. Increasing this number slows down signing and 
verifying linearly, and also increases the size of the 
signatures linearly.

Bitcoin public and private keys are used to generate the 
signatures. You may generate your own keypairs with the 
set-generate function described below. Bitcoin addresses 
are also generated.

When in default (unique) mode, signatures are generated 
with the prefix '1' and contain immutable Hx, Hy values 
as the first two bigints in the signature. These are 
immutable per message and private key. That is, any 
single message signed with the same private key and 
keyring will always generate the same Hx, Hy values, so 
for this single message you can identify if multiple 
members of the keyring have signed (but not which one).

Signature blinding has also been implemented. Blind 
signatures are prefixed with '2'. While blind signatures 
lose their Hx, Hy uniqueness, they use an ephemeral key 
to generate that signature that is afterwards discarded. 
This will prevents someone in the future from being able 
to identify which member of the ring signaturesigned the
message, even if all private keys for the public keys in 
the keyring are later revealed.

For more information on signature blinding, refer to 
[this link](https://download.wpsoftware.net/bitcoin/wizardry/ringsig-blinding.txt).


## Requirements
[Go](http://golang.org) 1.2 or newer.

## Installation
With Go installed, run the following command:
  ```$ go get github.com/monero-project/urs/...```

## Usage
  -B=false: Enable signature blinding (non-unique!); B|blind
  
  -S="": Load a Base58 signature to verify; S|sig (filename)
  
  -b="": Verify a binary message; b|verify-bin (filename)

  -blind=false: Enable signature blinding (non-unique!); B|blind
  
  -g="": Generates to a new keypair; g|set-generate (filename)
  
  -k="": Load a keyring of pubkeys; k|keyring (filename)
  
  -keypair="": Load a keypair to sign from; p|keypair (filename)
  
  -keyring="": Load a keyring of pubkeys; k|keyring (filename)
  
  -p="": Load a keypair to sign from; p|keypair (filename)
  
  -s="": Sign a text message; s|verify-bin (filename)
  
  -set-generate="": Generates to a new keypair; g|set-generate (filename)
  
  -sig="": Load a Base58 signature to verify; S|sig (filename)
  
  -sign-bin="": Sign a text message; z|verify-bin (filename)
  
  -sign-text="": Sign a binary message; s|verify-bin (filename)
  
  -v="": Verify a text message; v|verify-text (filename)
  
  -verify-bin="": Verify a binary message; b|verify-bin (filename)
  
  -verify-text="": Verify a text message; v|verify-text (filename)
  
  -z="": Sign a binary message; z|verify-bin (filename)

## Example usage

Generate signature example

```$ urs -sign-bin urs -keypair pair.key -keyring pubkeyring.keys > signature```

Verify signature example

```$ urs -verify-bin urs -sig signature -keyring pubkeyring.keys```

## Acknowledgements

- Andytoshi and Gmaxwell for their signature blinding scheme.

- Conformal Systems for generating the btcec lib, so that secp256k1 could be used.

- Hein Meling for the initial library for the ring signatures.
