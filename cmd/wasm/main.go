package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"syscall/js"
	"time"
)

type User struct {
	ID             string         `json:"id,omitempty"`
	Name           string         `json:"name"`
	Bio            string         `json:"bio,omitempty"`
	PublicKey      *rsa.PublicKey `json:"-"`
	PublicKeyBytes []byte         `json:"public_key,omitempty"`
	Preferences    []byte         `json:"preferences,omitempty"`
	JWT            string         `json:"jwt,omitempty"`       // not persisted server-side
	LoginMsg       []byte         `json:"login_msg,omitempty"` // not persisted server-side
	LoginSig       []byte         `json:"login_sig,omitempty"` // not persisted server-side
}

type LoginMessage struct {
	Time int64  `json:"time"`
	Name string `json:"name"`
}

func genNewAESKey(l int) string {
	var klen int = 16
	if l > 0 {
		klen = l
	}
	key := make([]byte, klen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	hk := hex.EncodeToString(key)
	return hk
}

func aesEncrypt(key []byte, raw []byte) (map[string]any, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, raw, nil)
	res := map[string]any{
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ciphertext),
	}
	return res, nil
}

func aesDecrypt(kd []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kd)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	raw, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func generateKeyPair(this js.Value, args []js.Value) any {
	kp := map[string]any{
		"public":  nil,
		"private": nil,
		"error":   nil,
	}
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		js.Global().Get("console").Call("log", "generateRSAKey error: "+err.Error())
		kp["error"] = err.Error()
		return kp
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privBytes := pem.EncodeToMemory(privateKeyBlock)
	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		js.Global().Get("console").Call("log", "generateRSAKey error: "+err.Error())
		kp["error"] = err.Error()
		return kp
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pubBytes := pem.EncodeToMemory(publicKeyBlock)
	kp["public"] = string(pubBytes)
	kp["private"] = string(privBytes)
	return kp
}

func (u *User) LoadPubKey() error {
	block, _ := pem.Decode(u.PublicKeyBytes)
	if block == nil {
		return errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)
	u.PublicKey = pub
	return nil
}

func CreateLoginJSON(name string, privKey []byte, pubKey []byte) ([]byte, error) {
	pk, err := BytesToPrivKey(privKey)
	if err != nil {
		return nil, err
	}
	u := &User{
		Name:           name,
		PublicKeyBytes: pubKey,
	}
	if err := u.LoadPubKey(); err != nil {
		return nil, err
	}
	lm := &LoginMessage{
		Time: time.Now().Unix(),
		Name: name,
	}
	lmBytes, err := json.Marshal(lm)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(lmBytes, pk)
	if err != nil {
		return nil, err
	}
	u.LoginMsg = lmBytes
	u.LoginSig = sig
	uBytes, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	return uBytes, nil
}

func HashSumMessage(msg []byte) []byte {
	// sha256 hash of message
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}

func Sign(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hs := HashSumMessage(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hs)
}

func BytesToPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

func BytesToPrivKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	return priv, nil
}

func rsaEncryptData(publicKey []byte, origData []byte) ([]byte, error) {
	pub, err := BytesToPubKey(publicKey)
	if err != nil {
		return nil, err
	}
	d, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, origData, nil)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func pubKeyFromPrivate(this js.Value, args []js.Value) any {
	priv, err := BytesToPrivKey([]byte(args[0].String()))
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)
	return js.ValueOf(string(publicKeyPem))
}

func rsaDecryptData(privateKey []byte, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	d, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func createLoginPayload(this js.Value, args []js.Value) any {
	name := args[0].String()
	privKey := []byte(args[1].String())
	pubKey := []byte(args[2].String())
	payload, err := CreateLoginJSON(name, privKey, pubKey)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	return js.ValueOf(string(payload))
}

func main() {
	done := make(chan struct{}, 0)
	js.Global().Set("wisp_GenerateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("wisp_CreateLoginJSON", js.FuncOf(createLoginPayload))
	<-done
}
