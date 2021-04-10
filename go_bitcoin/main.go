package main

func main () {
	//创建一个区块链, 指定输出地址
	bc := NewBlockChain("1KzwEHm9adpgyT3DhDQPX7m99wQ4juXtiw")
	//调用命令行命令
	cli := CLI{bc}
	//处理相应请求
	cli.Run()
}