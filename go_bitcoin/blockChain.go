package main

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"integration/lib/bolt"
)

const blockChianDb = "blockChain.db"
const blockBucket = "blockBucket"

type BlockChain struct {
	//key是区块的hash值，value为区块的字节流
	db *bolt.DB
	//存储最后一个区块的哈希
	tail []byte
}

//创建区块链
func NewBlockChain (address string) *BlockChain{

	//最后一个区块的哈希,从数据库中读出来的
	var lastHash []byte

	//打开数据库
	db, err := bolt.Open(blockChianDb, 0600, nil)

	if err != nil{
		log.Panic(err)
	}

	//写数据
	db.Update(func(tx *bolt.Tx) error {
		//找到bucket,(如果没有就创建，没有要找的bucket就代表要对一个新链进行操作，否则就是已有的链，进行追加即可)
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket == nil {
			//创建
			bucket, err = tx.CreateBucket([]byte(blockBucket))
			if err != nil {
				log.Panic("创建bucket(b1)失败")
			}

			//定义创世块
			genesisBlock := GenesisBlock(address)
			//block的哈希作为key，block的字节流作为value
			bucket.Put(genesisBlock.Hash, genesisBlock.Serialize())
			//修改最后一个区块的哈希
			bucket.Put([]byte("LastHashKey"), genesisBlock.Hash)

			lastHash = genesisBlock.Hash
		}else {
			lastHash = bucket.Get([]byte("LastHashKey"))
		}

		return nil
	})

	//返回刚刚操作的区块链
	return &BlockChain{
		db:   db,
		tail: lastHash,
	}
}
//定义创世块
func  GenesisBlock(address string) *Block {
	coinbase := NewCoinbaseTX(address, "创世块!")
	return NewBlock([]*Transaction{coinbase}, []byte{})

}

//添加区块到区块链
func (bc *BlockChain) AddBlock (txs []*Transaction) {

	for _, tx := range txs{
		if !bc.VerifyTransaction(tx){
			fmt.Printf("矿工发现无效交易\n")
			return
		}
	}
	//获取区块链
	db := bc.db
	//获取最后一个区块哈希
	lastHash := bc.tail

	db.Update(func(tx *bolt.Tx) error {

		//完成区块添加
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket == nil {
			log.Panic("bucket 不应该为空，请检查！")
		}

		//1. 创建新区块
		block := NewBlock(txs, lastHash)

		//2. 添加区块到数据库中，hash作为key, block的字节流作为value
		bucket.Put(block.Hash, block.Serialize())
		bucket.Put([]byte("LastHashKey"), block.Hash)

		//3. 更新内存中的区块链
		bc.tail = block.Hash

		return nil
	})
}

//反向打印区块
func (bc *BlockChain) Printchain(){
	//区块高度
	blockHeight := 0

	bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("blockBucket"))

		//从第一个key -> value进行遍历，到最后一个固定的key时直接返回
		b.ForEach(func(k, v []byte) error {
			if bytes.Equal(k, []byte("LastHashKey")){
				return nil
			}

			block := Deserialize(v)
			fmt.Printf("==============区块高度：%d=============\n", blockHeight)
			blockHeight++
			fmt.Printf("版本号: %d\n", block.Version)
			fmt.Printf("前区块哈希: %x\n", block.PrevHash)
			fmt.Printf("梅克尔根: %x\n", block.MerkelRoot)
			fmt.Printf("时间戳: %d\n", block.TimeStamp)
			fmt.Printf("难度值: %d\n", block.Difficulty)
			fmt.Printf("随机数: %d\n", block.Nonce)
			fmt.Printf("当前区块哈希: %x\n", block.Hash)
			fmt.Printf("区块数据: %s\n", block.Transactions[0].TXInputs[0].PubKey)
			return nil
		})
		return nil
	})
}

//找到指定地址的所有utxo
func (bc *BlockChain)FindUTXOs(pubKeyHash []byte) []TXOutput {
	var UTXO []TXOutput

	//找到地址的所有交易
	txs := bc.FindUTXOTransactions(pubKeyHash)
	for _, tx := range txs {
		for _, output := range tx.TXOutputs {
			if bytes.Equal(pubKeyHash, output.PubKeyHash){
				UTXO = append(UTXO, output)
			}
		}
	}
	return UTXO
}

func (bc *BlockChain) FindUTXOTransactions(senderPubKeyHash []byte)[]*Transaction{

	//存储所有包含utxo交易集合
	var txs []*Transaction

	//定义一个map来保存消费过的output，key是这个output的交易id, value是这个交易中索引的数组
	spentOutputs := make(map[string][]int64)

	//创建迭代器
	it := bc.NewIterator()

	//1.遍历区块
	for{
		block := it.Next()

	OUTPUT:
		//2.遍历交易
		for _, tx := range block.Transactions{
			//3.遍历output，找到和地址相关的utxo（在添加output之前检查一下是否已经消耗过）
			for i, output := range tx.TXOutputs{
				//如果当前的交易id存在于我们标识的map中，那么说明这个交易里面有消耗过的output
				if spentOutputs[string(tx.TXID)] != nil{
					for _, j := range spentOutputs[string(tx.TXID)]{
						if int64(i) == j{
							//当前准备添加output已经消耗过，遍历下一个交易
							continue OUTPUT
						}
					}
				}
				//判断output和目标的地址是否相同，满足条件，加到返回UTXO数组中
				if bytes.Equal(output.PubKeyHash, senderPubKeyHash){
					txs = append(txs, tx)
				}
			}

			//4.遍历input，找到和自己花费过的utxo集合（把自己消耗过的utxo标识出来）
			//如多当前交易是挖矿交易，不做遍历，直接跳过
			if !tx.IsCoinbase(){
				for _, input := range tx.TXInputs{
					//判断一下当前的这个input和目标是否一致，如果相同说明这个是本人消耗过的output，就加进来
					pubKeyHash := HashPubKey(input.PubKey)
					if bytes.Equal(pubKeyHash, senderPubKeyHash){
						spentOutputs[string(input.Txid)] = append(spentOutputs[string(input.Txid)], input.Index)
					}
				}
			}
		}

		if len(block.PrevHash) == 0{
			break
		}
	}
	return txs
}

//根据需求找到合理的utxo
func (bc *BlockChain) FindNeedUTXOs(senderPubKeyHash []byte, amount float64) (map[string][]uint64, float64) {
	//找到的合理uutxos集合
	utxos := make(map[string][]uint64)
	//找到的utxos里面包含的总数
	var calc float64

	txs := bc.FindUTXOTransactions(senderPubKeyHash)
	for _, tx := range txs {
		for i, output := range tx.TXOutputs {
			if bytes.Equal(senderPubKeyHash, output.PubKeyHash){
				if calc < amount {
					//1. 把utxo加进来
					utxos[string(tx.TXID)] = append(utxos[string(tx.TXID)], uint64(i))
					//2. 统计一下当前utxo的总额
					calc += output.Value
					if calc >= amount {
						fmt.Printf("找到了满足的金额： %f\n", calc)
						return utxos, calc
					}
				} else {
					fmt.Printf("不满足转账金额，当前金额：%f, 目标金额：%f\n", calc, amount)
				}
			}
		}
	}
	return utxos, calc
}

//根据id查找交易本身，遍历整个区块链
func(bc *BlockChain) FindTransactionByTXid(id []byte) (Transaction, error){

	//1.遍历区块链
	it := bc.NewIterator()
	for{
		block := it.Next()

		//2.遍历交易
		for _, tx := range block.Transactions{
			//3.比较交易，找到了直接退出
			if bytes.Equal(tx.TXID, id){
				return *tx, nil
			}
		}
		if len(block.PrevHash) == 0{
			break
		}
	}
	//4.如果没找到，返回空的Transaction，同时返回错误状态
	return Transaction{}, errors.New("无效的交易id, 请检查！\n")
}

func (bc *BlockChain) SignTransaction(tx *Transaction, privateKey *ecdsa.PrivateKey){
	//签名，交易创建的最后进行签名
	prevTXs := make(map[string]Transaction)

	//找到所有引用的交易
	// 1. 根据inputs来找，有多少inputs，就遍历多少次
	for _, input := range tx.TXInputs{
		//2.根据id查找交易本身，需要遍历整个区块链
		tx, err := bc.FindTransactionByTXid(input.Txid)

		if err != nil{
			log.Panic(err)
		}

		//3.添加到prevTXs里面
		prevTXs[string(input.Txid)] = tx
	}
	tx.Sign(privateKey, prevTXs)
}

func (bc *BlockChain) VerifyTransaction(tx *Transaction) bool{

	if tx.IsCoinbase(){
		return true
	}

	//签名，交易创建的最后进行签名
	prevTXs := make(map[string]Transaction)

	//找到所有引用的交易
	// 1. 根据inputs来找，有多少inputs，就遍历多少次
	for _, input := range tx.TXInputs{
		//2.根据id查找交易本身，需要遍历整个区块链
		tx, err := bc.FindTransactionByTXid(input.Txid)

		if err != nil{
			log.Panic(err)
		}
		// 3.添加到prevTXs里面
		prevTXs[string(input.Txid)] = tx
	}

	return tx.Verify(prevTXs)
}