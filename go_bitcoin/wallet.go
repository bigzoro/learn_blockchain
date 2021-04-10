package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"integration/lib/base58"
	"integration/lib/ripemd160"
)

//这里的钱包是一种结构，每一个钱包保存了公钥和私钥对

type Wallet struct {
	//私钥
	Private *ecdsa.PrivateKey

	//公钥
	//约定，这里的PubKey不存储原始的公钥，而是存储X和Y拼接的字符串，在校验端重新拆分
	PubKey []byte
}

//创建钱包
func NewWalet() *Wallet{

	//创建曲线
	curve := elliptic.P256()
	//生成私钥
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil{
		log.Panic(err)
	}

	//生成公钥
	pubKeyOrig := privateKey.PublicKey

	//拼接X和Y
	pubKey := append(pubKeyOrig.X.Bytes(), pubKeyOrig.Y.Bytes()...)

	return &Wallet{
		Private: privateKey,
		PubKey:  pubKey,
	}
}
//生成地址
func (w *Wallet) NewAdress() string{

	//1. 公钥
	pubKey := w.PubKey

	//2. RIPEMD160
	rip160HashValue := HashPubKey(pubKey)

	version := byte(00)
	//3. 拼接version
	payload := append([]byte{version}, rip160HashValue...)

	//4. 校验码
	checkCode := CheckSum(payload)

	//25字节数据
	payload = append(payload, checkCode...)

	//5. base58编码
	address := base58.Encode(payload)

	//返回地址
	return address
}

//得到公钥哈希
func HashPubKey(data []byte) []byte{
	//sha256
	hash := sha256.Sum256(data)

	//RIPE160
	ripe160hasher := ripemd160.New()
	_, err := ripe160hasher.Write(hash[:])
	if err != nil {
		log.Panic(err)
	}
	
	//返回ripe160的哈希结果
	ripe160hashValue := ripe160hasher.Sum(nil)

	return ripe160hashValue
}

//校验地址是否正确
func IsValidAddress(address string) bool{
	//1.解码
	addressByte := base58.Decode(address)

	if len(addressByte) < 4{
		return false
	}
	//2.取数据
	payload := addressByte[:len(addressByte)-4]
	checksum1 := addressByte[len(addressByte)-4:]
	//3.做checksum函数
	checksum2 := CheckSum(payload)
	//4.比较
	return bytes.Equal(checksum1, checksum2)
}

func CheckSum(data []byte) []byte{

	//两次哈希
	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(hash1[:])

	//前4字节校验码
	checkCode := hash2[:4]

	return checkCode
}