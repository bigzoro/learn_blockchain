package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
)

//定义proofOfWork结构
type ProofOfWork struct {
	//a. block
	block *Block
	//b. 目标值
	target *big.Int
}
//提供创建POW函数
func NewProofOfWork(block *Block) *ProofOfWork{
	pow := ProofOfWork{
		block:  block,
	}
	//难度值
	targetStr := "0000f00000000000000000000000000000000000000000000000000000000000"

	//引入辅助变量，将targetStr抓换为big.int
	tmpInt := big.Int{}
	tmpInt.SetString(targetStr, 16)

	pow.target = &tmpInt
	return &pow
}
//提供不断计算的函数
func (pow *ProofOfWork) Run () ([]byte, uint64) {
	//拼装数据
	var nonce uint64
	block := pow.block
	var hash [32]byte

	fmt.Printf("开始挖矿...\n")
	for{
		tmp := [][]byte{
			Uint64ToByte(block.Version),
			block.PrevHash,
			block.MerkelRoot,
			Uint64ToByte(block.TimeStamp),
			Uint64ToByte(block.Difficulty),
			Uint64ToByte(nonce),
		}
		blockInfo := bytes.Join(tmp, []byte{})
		//做hash运算
		hash = sha256.Sum256(blockInfo)
		tmpInt := big.Int{}
		tmpInt.SetBytes(hash[:])
		//与目标值比较
		if tmpInt.Cmp(pow.target) == -1{
			//找到了
			fmt.Printf("挖矿成功！ hash: %x, nonce: %d\n", hash, nonce)
			return hash[:], nonce
		}else {
			//没到到 nonce加1
			nonce ++
		}

	}
}

