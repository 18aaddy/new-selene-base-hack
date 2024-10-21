package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/BlocSoc-iitr/selene/client"
	"github.com/BlocSoc-iitr/selene/config"
	"github.com/BlocSoc-iitr/selene/execution"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func MakeNewNode() (*client.Node, *execution.State) {
	var n config.Network
	baseConfig, err := n.BaseConfig("MAINNET")
	if err != nil {
		fmt.Printf("Error in base config creation: %v", err)
	}

	checkpoint := "b21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5"
	consensusRpcUrl := "http://testing.mainnet.beacon-api.nimbus.team"
	executionRpcUrl := "https://eth-mainnet.g.alchemy.com/v2/j28GcevSYukh-GvSeBOYcwHOfIggF1Gt"

	config := &config.Config{
		ConsensusRpc:         consensusRpcUrl,
		ExecutionRpc:         executionRpcUrl,
		RpcBindIp:            &baseConfig.RpcBindIp,
		RpcPort:              &baseConfig.RpcPort,
		DefaultCheckpoint:    baseConfig.DefaultCheckpoint,
		Checkpoint:           (*[32]byte)(common.Hex2Bytes(checkpoint)),
		Chain:                baseConfig.Chain,
		Forks:                baseConfig.Forks,
		StrictCheckpointAge:  false,
		DataDir:              baseConfig.DataDir,
		DatabaseType:         nil,
		MaxCheckpointAge:     baseConfig.MaxCheckpointAge,
		LoadExternalFallback: false,
	}

	node, state, err := client.NewNode(config)
	if err != nil {
		fmt.Printf("Error in node creation: %v", err)
	}
	return node, state
}

func main() {
	node, _ := MakeNewNode()
	blockHash := common.HexToHash("0x332b3105be36902ba797df9b0b8a92ce21dbff46c4f8cd33d437ee546f341836")
	address := common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
	address2 := common.HexToAddress("0x398D07F671A5252C168fEdeD58FB1A30432d49A3")
	filter := ethereum.FilterQuery{BlockHash: &blockHash, FromBlock: big.NewInt(21007177), ToBlock: big.NewInt(21007179), Addresses: []common.Address{address, address2}}

	logsChan := make(chan []types.Log)
	errorChan := make(chan error)
	go func() {
		logs, err := node.GetLogs(&filter)
		if err != nil {
			errorChan <- err
			return
		}
		logsChan <- logs
		errorChan <- nil
	}()

	select {
	case logs := <-logsChan:
		fmt.Println("\nFetched Log")
		PrintLog(logs[0])
	case err := <-errorChan:
		fmt.Printf("Got error while fetching logs: %v", err)
	}
}

func PrintLog(log types.Log) {
    fmt.Printf(`
Log Details:
-----------
Address:     %s
Topics:      %s
Data:        %s
BlockNumber: %d
TxHash:      %s
TxIndex:     %d
BlockHash:   %s
Index:       %d
Removed:     %v

`,
        log.Address.Hex(),
        formatTopics(log.Topics),
        formatData(log.Data),
        log.BlockNumber,
        log.TxHash.Hex(),
        log.TxIndex,
        log.BlockHash.Hex(),
        log.Index,
        log.Removed)
}

// formatTopics formats the topics array in a readable way
func formatTopics(topics []common.Hash) string {
    if len(topics) == 0 {
        return "[]"
    }

    var builder strings.Builder
    builder.WriteString("[\n")
    for i, topic := range topics {
        builder.WriteString(fmt.Sprintf("    %d: %s\n", i, topic.Hex()))
    }
    builder.WriteString("  ]")
    return builder.String()
}

// formatData formats the data bytes in a readable hex format
func formatData(data []byte) string {
    if len(data) == 0 {
        return "0x"
    }
    return fmt.Sprintf("0x%s", hex.EncodeToString(data))
}