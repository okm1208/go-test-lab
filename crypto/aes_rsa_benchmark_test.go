// 이 패키지는 암호화와 관련된 코드들의 패키지 이다.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"
)

// 이 함수는 RSA를 사용하여 개인키와 공개키를 생성 하는 함수 이다.
func prepareRSA()(sourceData, label []byte, privateKey *rsa.PrivateKey){
	sourceData = make([]byte, 128)
	label = []byte("")
	io.ReadFull(rand.Reader, sourceData)

	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	return
}

// 이 함수는 공개키 기반 - 암호화 성능을 측정
func BenchmarkRSAEncryption(b *testing.B){
	sourceData, label, privateKey := prepareRSA()
	publicKey := &privateKey.PublicKey
	md5hash := md5.New()
	b.ResetTimer()
	for i:=0 ; i < b.N; i++ {
		rsa.EncryptOAEP(md5hash, rand.Reader, publicKey, sourceData, label)
	}
}
// 이 함수는 공개키 기반 - 복호화 성능을 측정
func BenchmarkRSADecryption(b *testing.B){
	sourceData, label, privateKey := prepareRSA()
	publicKey := &privateKey.PublicKey
	md5hash := md5.New()
	encrypted, _ := rsa.EncryptOAEP(md5hash, rand.Reader, publicKey, sourceData,label)

	b.ResetTimer()
	for i := 0 ; i < b.N; i++{
		rsa.DecryptOAEP(md5hash,rand.Reader, privateKey, encrypted, label)
	}
}

// 이 함수는 AES를 사용하여 대칭키를 생성 하는 함수 이다.
func prepareAES()( sourceData, nonce []byte,gcm cipher.AEAD){
	sourceData = make([]byte, 128)
	io.ReadFull(rand.Reader, sourceData)
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	nonce = make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)
	block , _ := aes.NewCipher(key)
	gcm, _ = cipher.NewGCM(block)
	return
}
// 이 함수는 대칭키 기반 - 암호화 성능을 측정
func BenchmarkAESEncryption(b *testing.B){
	sourceData , nonce, gcm := prepareAES()
	b.ResetTimer()

	for i := 0; i < b.N ; i++ {
		gcm.Seal(nil, nonce, sourceData, nil)
	}
}

// 이 함수는 대칭키 기반 - 복호화 성능을 측정
func BenchmarkAESDecryption(b *testing.B){
	sourceData, nonce, gcm := prepareAES()
	encrypted := gcm.Seal(nil , nonce, sourceData, nil )

	b.ResetTimer()
	for i:=0 ; i < b.N ; i++ {
		gcm.Open(nil , nonce, encrypted,nil )
	}
}