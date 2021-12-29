package main

import (
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	buyingAddress := common.HexToAddress("")

	client, err := ethclient.Dial("https://bsc-dataseed1.defibit.io/")
	if err != nil {
		log.Fatal(err)
	}

}
