package attestation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"crypto/x509"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Document represents the AWS Nitro Enclave Attestation Document.
type AttestationDocument struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

type EnclaveConfig struct {
	TotalMemory uint64 `json:"total_memory"`
	TotalCpus   uint64 `json:"total_cpus"`
}
type coseSign1 struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

func Verifier(endpoint string, pcrs map[uint]string, minCpus uint64, minMem uint64, maxAge int64) ([]byte, error) {
	// get attestation document
	doc, err := getAttestationDoc(endpoint)
	if err != nil {
		return nil, err
	}
	// verify
	return verify(doc, pcrs, minCpus, minMem, maxAge)
}

func getAttestationDoc(endpoint string) ([]byte, error) {
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func verify(data []byte, pcrs map[uint]string, minCpus uint64, minMem uint64, maxAge int64) ([]byte, error) {
	// parse attestation document
	coseObj := coseSign1{}
	err := cbor.Unmarshal(data, &coseObj)
	if err != nil {
		return nil, errors.New("cbor bad coseSign1")
	}
	doc := AttestationDocument{}
	err = cbor.Unmarshal(coseObj.Payload, &doc)
	if nil != err {
		return nil, errors.New("cbor bad attestation document")
	}

	// verify PCRs
	for index, value := range pcrs {
		doc_pcr, found := doc.PCRs[index]
		if !found {
			return nil, fmt.Errorf("pcr%d not found", index)
		}
		if value != hex.EncodeToString(doc_pcr) {
			return nil, fmt.Errorf("pcr%d match failed", index)
		}
	}

	// validating Signature
	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, errors.New("certificate parsing failed")
	}
	publicKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.New("public key parsing failed")
	}
	var sign1MessagePrefix = []byte{
		0xd2, // #6.18
	}
	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(append(sign1MessagePrefix[:], data[:]...))
	if err != nil {
		return nil, errors.New("coseSign1Message unmarshal failed")
	}
	algorithm, _ := msg.Headers.Protected.Algorithm()
	verifier, _ := cose.NewVerifier(algorithm, publicKey)

	// Verify the signature using the public_key (`*rsa.PublicKey`, `*ecdsa.PublicKey`, and `ed25519.PublicKey` are accepted)
	if msg.Verify(nil, verifier) != nil {
		return nil, errors.New("cose signature verification failed")
	}

	// Validating certificate chain
	rootCert, err := os.ReadFile("aws.cert")
	if err != nil {
		return nil, errors.New("root certificate reading failed")
	}
	if err := verifyCertChain(cert, doc.CABundle, rootCert); err != nil {
		return nil, err
	}

	// verify enclave size
	var userData EnclaveConfig
	if err := json.Unmarshal(doc.UserData, &userData); err != nil {
		return nil, errors.New("userData parse failed")
	}
	if userData.TotalCpus < minCpus {
		return nil, errors.New("enclave does not meet minimum cpus requirement")
	}
	if userData.TotalMemory < minMem {
		return nil, errors.New("enclave does not meet minimum memory requirement")
	}

	// verify age
	now := time.Now().UnixMilli()
	if (now - maxAge) > int64(doc.Timestamp) {
		return nil, errors.New("attestation is too old")
	}

	// return public key
	return doc.PublicKey, nil
}

func verifyCertChain(cert *x509.Certificate, cabundle [][]byte, rootCertPem []byte) error {
	intermediates, err := x509.ParseCertificates(concatCerts(cabundle))
	if err != nil {
		return errors.New("cabundle parsing failed")
	}

	root, err := x509.ParseCertificate(rootCertPem)
	if err != nil {
		return err
	}
	if !root.Equal(intermediates[0]) {
		return errors.New("root certificate mismatch")
	}

	pool1 := x509.NewCertPool()
	pool2 := x509.NewCertPool()

	for _, intercert := range intermediates {
		pool1.AddCert(intercert)
	}
	pool2.AddCert(root)
	opts := x509.VerifyOptions{
		Intermediates: pool1,
		Roots:         pool2,
	}
	if _, err := cert.Verify(opts); err != nil {
		return errors.New("certificate chain verification failed")
	}
	return nil
}

func concatCerts(x interface{}) []byte {
	res := []byte{}
	for _, cert := range x.([]interface{}) {
		res = append(res, cert.([]byte)...)
	}
	return res
}
