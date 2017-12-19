package goRSA

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/asn1"
  "encoding/gob"
  "encoding/pem"
  "os"
)

func SaveGobKey(fileName string, key interface{}) error {
  outFile, err := os.Create(fileName)
  if err != nil {
    return err
  }

  defer outFile.Close()

  encoder := gob.NewEncoder(outFile)
  err = encoder.Encode(key)

  return err
}

func SavePEMKey(fileName string, key *rsa.PrivateKey) error {
  outFile, err := os.Create(fileName)
  if err != nil {
    return err
  }

  defer outFile.Close()

  var privateKey = &pem.Block{
    Type:  "PRIVATE KEY",
    Bytes: x509.MarshalPKCS1PrivateKey(key),
  }

  err = pem.Encode(outFile, privateKey)

  return err
}

func SavePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
  asn1Bytes, err := asn1.Marshal(pubkey)
  if err != nil {
    return err
  }

  var pemkey = &pem.Block{
    Type:  "PUBLIC KEY",
    Bytes: asn1Bytes,
  }

  pemfile, err := os.Create(fileName)
  if err != nil {
    return err
  }
  defer pemfile.Close()

  err = pem.Encode(pemfile, pemkey)
  return err
}
