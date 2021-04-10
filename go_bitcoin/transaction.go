package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"strings"
)

const reward = 12.5

//1. 定义交易结构
type Transaction struct {
	//交易ID
	TXID []byte
	//交易输入数组
	TXInputs []TXInput
	//交易输出数组
	TXOutputs []TXOutput
}

//定义交易输入
//解锁脚本：<Sig><PubKey>
type TXInput struct {
	//引用的交易ID
	Txid []byte
	//引用的output的索引值
	Index int64
	//数字签名，由r, s拼成的[]byte
	Signature []byte
	//这里的PubKey不是原始存储的公钥，而是存储X和Y拼接的字符串。在校验端重新拆分
	PubKey []byte
}

//定义交易输出
//锁定脚本：OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
type TXOutput struct {
	//转账金额
	Value float64
	//收款方的公钥哈希
	PubKeyHash []byte
}

//由于现在存储的字段是地址的公钥哈希，所以无法直接创建TXOutput,
//为了能够得到公钥哈希，我们需要处理一下
func (output *TXOutput) Lock (address string){
	//解锁
	output.PubKeyHash = GetPubKeyFromAddress(address)
}

//给TXOutput提供一个创建的方法，否则无法调用LLock
func NewTXOutput(value float64, address string) *TXOutput{
	output := TXOutput{
		Value:      value,
	}
	output.Lock(address)

	return &output
}

//设置交易ID
func (tx *Transaction) SetHash() {
	var buffer bytes.Buffer

	encoder := gob.NewEncoder(&buffer)

	err := encoder.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	data := buffer.Bytes()
	hash := sha256.Sum256(data)
	tx.TXID = hash[:]
}

//判断当前交易是否为挖矿交易
func (tx *Transaction) IsCoinbase() bool {
	if len(tx.TXInputs) == 1 && len(tx.TXInputs[0].Txid) == 0 && tx.TXInputs[0].Index == -1{
		return true
	}
	return false
}

//2. 创建挖矿交易coinbase
func NewCoinbaseTX(address string, data string) *Transaction{

	//挖矿交易特点, 1.只有一个input ，2. 无需引用交易id ，3. 无需引用index
	//创建输入
	input := TXInput{
		Txid:  []byte{},
		Index: -1,
		Signature:   nil,
		PubKey: []byte(data),
	}
	//创建输出
	output := NewTXOutput(reward, address)

	tx := Transaction{
		TXID:      []byte{},
		TXInputs:  []TXInput{input},
		TXOutputs: []TXOutput{*output},
	}

	//设置交易ID
	tx.SetHash()

	return &tx
}

//创建普通转账交易
func NewTransaction(from, to string, amount float64, bc *BlockChain) *Transaction{

	//通过钱包得到公私钥，签名时使用
	ws := NewWallets()
	wallet := ws.WalletsMap[from]
	if wallet == nil {
		fmt.Printf("没有找到该地址的钱包，交易创建失败！\n")
		return nil
	}

	pubKey := wallet.PubKey
	privateKey := wallet.Private

	//得到公钥哈希
	pubKeyHash := HashPubKey(pubKey)

	//1.找到最合理的UTXO集合
	utxos, resValue := bc.FindNeedUTXOs(pubKeyHash, amount)

	if resValue < amount{
		fmt.Printf("余额不足，交易失败！\n")
		return nil
	}

	var inputs []TXInput
	var outputs []TXOutput
	//2.创建交易输入将这些UTXO逐一转成inputs
	for id, indexArray := range utxos{
		for _, i := range indexArray{
			input := TXInput{
				Txid:  []byte(id),
				Index: int64(i),
				Signature:   nil,
				PubKey:	pubKey,
			}
			inputs = append(inputs, input)
		}
	}

	//3.创建交易输出
	output := NewTXOutput(amount, to)
	outputs= append(outputs, *output)

	//4.找零
	if resValue > amount{
		output = NewTXOutput(resValue - amount, from)
		outputs = append(outputs, *output)
	}

	tx := Transaction{
		TXID:      []byte{},
		TXInputs:  inputs,
		TXOutputs: outputs,
	}

	tx.SetHash()

	bc.SignTransaction(&tx, privateKey)

	return &tx
}

//签名的具体实现, 参数：私钥，inputs里面所有引用的交易的结构
func (tx *Transaction) Sign(privateKey *ecdsa.PrivateKey, prevTXs map[string]Transaction){
	//我们对每一个input都签名一次，签名的数据是由当前input引用的output的哈希+当前的outputs（都存在当前这个txCopy里面）
	if tx.IsCoinbase(){
		return
	}

	//1.创建一个当前交易的副本：txCopy，使用函数：TrimmedCopy：要把Signature和PubKey字段设置为null
	txCopy := tx.TrimmedCopy()

	//2.循环遍历txCopy的inputs，得到这个input索引的output的公钥哈希
	for i, input := range txCopy.TXInputs{
		prevTX := prevTXs[string(input.Txid)]

		if len(prevTX.TXID) == 0{
			log.Panic("引用的交易无效\n")
		}

		//a.设置副本输入的公钥
		txCopy.TXInputs[i].PubKey = prevTX.TXOutputs[input.Index].PubKeyHash

		//b.对拼好的txCopy进行哈希处理，SetHash得到TXID，这个TXID就是我们要签名的最终数据
		txCopy.SetHash()

		//还原，以免影响后面的input签名
		txCopy.TXInputs[i].PubKey = nil
		signDataHash := txCopy.TXID

		//4.执行签名动作，得到r,s字节流
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, signDataHash)
		if err != nil{
			log.Panic(err)
		}

		//5.放到我们签名的inputs的Signature中
		signature := append(r.Bytes(), s.Bytes()...)
		tx.TXInputs[i].Signature = signature
	}

}

//拷贝方法，用来引用交易
func (tx *Transaction) TrimmedCopy() Transaction{
	var inputs []TXInput
	var outputs []TXOutput

	for _, input := range tx.TXInputs{
		inputs = append(inputs, TXInput{input.Txid, input.Index, nil, nil})
	}

	for _, output := range tx.TXOutputs{
		outputs = append(outputs, output)
	}

	return Transaction{tx.TXID, inputs, outputs}
}

//分析校验
//所需要的数据：公钥、数据（txCopy、生成哈希）、签名
func (tx *Transaction) Verify (prevTXs map[string]Transaction) bool{

	if tx.IsCoinbase(){
		return true
	}

	//1.得到签名的数据
	txCopy := tx.TrimmedCopy()

	for i, input := range tx.TXInputs{
		prevTX := prevTXs[string(input.Txid)]
		if len(prevTX.TXID) == 0{
			log.Panic("引用的交易无效\n")
		}

		txCopy.TXInputs[i].PubKey = prevTX.TXOutputs[input.Index].PubKeyHash
		txCopy.SetHash()
		dataHash := txCopy.TXID

		//2.得到signature，反退回r,s
		signature := input.Signature

		//3拆解PubKey, X,Y得到原生公钥
		pubKey := input.PubKey

		r := big.Int{}
		s := big.Int{}

		r.SetBytes(signature[:len(signature)/2])
		s.SetBytes(signature[len(signature)/2:])

		X := big.Int{}
		Y := big.Int{}

		//pubKey平均分，前半部分给X，后半部分给Y
		X.SetBytes(pubKey[:len(pubKey)/2])
		Y.SetBytes(pubKey[len(pubKey)/2:])

		pubKeyOrigin := ecdsa.PublicKey{elliptic.P256(), &X, &Y}

		//4.Verify
		if !ecdsa.Verify(&pubKeyOrigin, dataHash, &r, &s){
			return false
		}

	}
	return true
}

func (tx Transaction) String() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("--- Transaction %x:", tx.TXID))

	for i, input := range tx.TXInputs {

		lines = append(lines, fmt.Sprintf("     Input %d:", i))
		lines = append(lines, fmt.Sprintf("       TXID:      %x", input.Txid))
		lines = append(lines, fmt.Sprintf("       Out:       %d", input.Index))
		lines = append(lines, fmt.Sprintf("       Signature: %x", input.Signature))
		lines = append(lines, fmt.Sprintf("       PubKey:    %x", input.PubKey))
	}

	for i, output := range tx.TXOutputs{
		lines = append(lines, fmt.Sprintf("     Output %d:", i))
		lines = append(lines, fmt.Sprintf("       Value:  %f", output.Value))
		lines = append(lines, fmt.Sprintf("       Script: %x", output.PubKeyHash))
	}

	return strings.Join(lines, "\n")
}
