package macaroon

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// pubKeyBytes is each single-key algorithm's public key length.
var pubKeyBytes = map[SigAlg]int{
	AlgEd25519:              ed25519.PublicKeySize,
	AlgEcdsaSecp256k1Sha256: 33,
}

// GenerateKey makes a fresh random key of the given algorithm.
func GenerateKey(alg SigAlg) (KeyPair, error) {
	switch alg {
	case AlgEd25519:
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return KeyPair{}, err
		}
		return KeyPairFromPrivate(alg, seed)
	case AlgEcdsaSecp256k1Sha256:
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return KeyPair{}, err
		}
		return KeyPairFromPrivate(alg, priv.Serialize())
	}
	return KeyPair{}, fmt.Errorf("unsupported key alg %q", alg)
}

// KeyPairFromPrivate builds a KeyPair from a known 32-byte private key.
func KeyPairFromPrivate(alg SigAlg, priv []byte) (KeyPair, error) {
	pub, err := PublicKeyBytes(alg, priv)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Alg: alg, Priv: priv, Pub: PubKey{Alg: alg, Key: BytesToHex(pub)}}, nil
}

// PublicKeyBytes derives the public key from a private key.
func PublicKeyBytes(alg SigAlg, priv []byte) ([]byte, error) {
	switch alg {
	case AlgEd25519:
		return Ed25519PublicKey(priv)
	case AlgEcdsaSecp256k1Sha256:
		return EcdsaSecp256k1PublicKey(priv)
	}
	return nil, fmt.Errorf("unsupported key alg %q", alg)
}

// SignWith signs msg with a private key of the given algorithm.
func SignWith(alg SigAlg, priv, msg []byte) ([]byte, error) {
	switch alg {
	case AlgEd25519:
		return Ed25519Sign(priv, msg)
	case AlgEcdsaSecp256k1Sha256:
		return EcdsaSecp256k1Sign(priv, msg)
	}
	return nil, fmt.Errorf("unsupported key alg %q", alg)
}

// VerifyWith checks a hex signature against a public key, by the key's
// algorithm.
func VerifyWith(pub PubKey, msg []byte, sigHex string) bool {
	key, err := HexToBytes(pub.Key)
	if err != nil || len(key) != pubKeyBytes[pub.Alg] {
		return false
	}
	sig, err := HexToBytes(sigHex)
	if err != nil {
		return false
	}
	switch pub.Alg {
	case AlgEd25519:
		return Ed25519Verify(key, msg, sig)
	case AlgEcdsaSecp256k1Sha256:
		return EcdsaSecp256k1Verify(key, msg, sig)
	}
	return false
}
