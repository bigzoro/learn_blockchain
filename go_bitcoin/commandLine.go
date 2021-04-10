package main

import (
	"fmt"
)

//正向打印
func (cli *CLI)PrintBlockChain(){
	cli.bc.Printchain()
	fmt.Printf("打印区块完成！\n")
}

//反向打印
func (cli *CLI) PrintBlockChainReverse(){
	bc := cli.bc
	//创建迭代器
	it := bc.NewIterator()
	for{
		//返回区块并左移
		block := it.Next()
		for _, tx := range block.Transactions{
			fmt.Println(tx)
		}

		if len(block.PrevHash) == 0 {
			fmt.Printf("区块遍历完成！\n")
			break
		}
	}
}

//获取指定账户余额
func (cli *CLI)GetBalance(address string){

	//1. 校验地址
	if !IsValidAddress(address){
		fmt.Printf("地址无效：%s\n", address)
		return
	}
	//2. 生成公钥哈希
	pubKeyHash := GetPubKeyFromAddress(address)
	//3. 通过公钥哈希找到所有的UTXO
	utxos := cli.bc.FindUTXOs(pubKeyHash)

	total := 0.0

	for _, utxo := range utxos{
		total += utxo.Value
	}

	fmt.Printf("\"%s\"的余额为：%f\n", address, total)
}

//创建钱包
func(cli *CLI)NewWallet(){
	ws := NewWallets()
	address := ws.CreateWallet()
	fmt.Printf("地址：%s\n", address)
}

//获取所有钱包地址
func (cli *CLI) ListAddresses(){
	ws := NewWallets()
	addresses := ws.ListAllAddress()

	for _, address := range addresses{
		fmt.Printf("地址：%s\n", address)
	}
}

//发送交易
func (cli *CLI) Send(from, to string, amount float64, miner, data string){

	//1. 校验地址
	if !IsValidAddress(from){
		fmt.Printf("地址无效 from：%s\n", from)
		return
	}
	if !IsValidAddress(to){
		fmt.Printf("地址无效 to：%s\n", to)
		return
	}
	if !IsValidAddress(miner){
		fmt.Printf("地址无效 miner：%s\n", miner)
		return
	}

	//2. 创建挖矿交易
	coinbase := NewCoinbaseTX(miner, data)

	//3. 创建一个普通交易
	tx := NewTransaction(from, to, amount, cli.bc)
	if tx == nil {
		fmt.Printf("无效交易!\n")
		return
	}
	//4. 添加到区块
	cli.bc.AddBlock([]*Transaction{coinbase, tx})
	fmt.Printf("转账成功！\n")
}



