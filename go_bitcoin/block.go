package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"log"
	"time"
)

//定义简单区块结构
type Block struct {
	//版本
	Version uint64
	//前区块哈希
	PrevHash []byte
	//Merkel根
	MerkelRoot []byte
	//时间戳
	TimeStamp uint64
	//难度值
	Difficulty uint64
	//随机数
	Nonce uint64
	//当前区块哈希,正常情况下比特币区块中没有当前区块哈希，我们为了方便做了简化
	Hash []byte

	//真实的交易数组
	Transactions []*Transaction
}

//辅助函数，将uint64转化为[]byte
func Uint64ToByte(num uint64) []byte{
	var buffer bytes.Buffer

	err := binary.Write(&buffer, binary.BigEndian, num)
	if err != nil{
		log.Panic(err)
	}
	return buffer.Bytes()
}

//添加区块函数
func NewBlock (txs []*Transaction, prevBlockHash []byte) *Block{
	block := Block{
		Version:    00,
		PrevHash:   prevBlockHash,
		MerkelRoot: []byte{},
		TimeStamp:  uint64(time.Now().Unix()),
		Difficulty: 0,
		Nonce:      0,
		Hash:       []byte{},
		Transactions: txs,
	}

	block.MerkelRoot = block.MakeMerkelRoot()

	//创建一个pow对象
	pow := NewProofOfWork(&block)
	hash, nonce := pow.Run()

	//根据挖矿结果对区块进行更新
	block.Hash= hash
	block.Nonce = nonce

	return &block
}

//序列化，使用gob进行序列化（编码）得到字节流
func (block *Block) Serialize () []byte {
	var buffer bytes.Buffer

	//1. 定义一个编码器
	encoder := gob.NewEncoder(&buffer)
	//2. 使用编码器进行编码
	err := encoder.Encode(&block)
	if err != nil{
		log.Panic("编码出错！")
	}

	return buffer.Bytes()
}

//反序列化
func Deserialize (data []byte) Block {
	//定义一个解码器
	decoder := gob.NewDecoder(bytes.NewReader(data))

	var block Block

	//使用解码器进行解码
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic("解码出错！")
	}
	return block
}

//用区块数据模拟梅克尔根
func (block *Block)MakeMerkelRoot() []byte{
	var info []byte

	for _, tx := range block.Transactions{
		info = append(info, tx.TXID...)
	}

	hash := sha256.Sum256(info)
	return hash[:]
}