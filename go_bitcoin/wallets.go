package main

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"io/ioutil"
	"log"
	"os"
	"integration/lib/base58"
)

const walletFile = "wallet.dat"

//定义一个wwallets结构，它保存所有的wallet以及它的地址
type Wallets struct {
	//map[地址]钱包
	WalletsMap map[string] *Wallet
}
//创建方法，返回当前所有钱包的实例
func NewWallets() *Wallets{
	var ws Wallets
	ws.WalletsMap = make(map[string]*Wallet)
	ws.loadFile()
	return &ws
}

func (ws *Wallets) CreateWallet() string{
	wallet := NewWalet()
	address := wallet.NewAdress()

	ws.WalletsMap[address] = wallet

	ws.savaToFile()

	return address
}
//保存方法，把所有新建的wallet添加进去
func (ws *Wallets) savaToFile(){

	var buffer bytes.Buffer

	gob.Register(elliptic.P256())
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(ws)
	if err != nil{
		log.Panic(err)
	}
	ioutil.WriteFile(walletFile, buffer.Bytes(), 0600)
}

//读取本地所有钱包
func (ws *Wallets) loadFile(){
	//在读取之前，确认文件是否存在，如果不存在，直接退出
	_, err := os.Stat(walletFile)
	if os.IsNotExist(err){
		return
	}

	//读取钱包
	content, err := ioutil.ReadFile(walletFile)
	if err != nil {
		log.Panic(err)
	}

	//解码
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(content))

	var wsLocal Wallets
	err = decoder.Decode(&wsLocal)
	if err != nil{
		log.Panic(err)
	}

	ws.WalletsMap = wsLocal.WalletsMap
}

func (ws *Wallets) ListAllAddress() []string{
	var addresses []string

	//遍历钱包，将所有的key取出来返回
	for address := range ws.WalletsMap{
		addresses = append(addresses, address)
	}

	return addresses
}

//通过地址返回公钥的哈希值
func GetPubKeyFromAddress(address string) []byte{
	//1. 解码，得到25字节数据
	addressByte := base58.Decode(address)

	//2. 截取出公钥哈希：去除version（1字节），去除校验码（4字节）
	len := len(addressByte)
	pubKeyHash := addressByte[1:len-4]

	return pubKeyHash
}