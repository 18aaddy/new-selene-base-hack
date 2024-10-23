package client

import (
	// "log"
	"math/big"
	// "math/big"
	"fmt"
	// "log"

	"testing"
	// "time"

	// "encoding/hex"

	// seleneCommon "github.com/BlocSoc-iitr/selene/common"
	// "github.com/BlocSoc-iitr/selene/client"
	"github.com/BlocSoc-iitr/selene/config"
	"github.com/BlocSoc-iitr/selene/execution"

	// "github.com/BlocSoc-iitr/selene/utils"

	// "github.com/BlocSoc-iitr/selene/consensus"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func MakeNewNode() (*Node, *execution.State) {
	var n config.Network
	baseConfig, err := n.BaseConfig("MAINNET")
	if err != nil {
		fmt.Printf("Error in base config creation: %v", err)
	}

	checkpoint := "b21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5"
	consensusRpcUrl := "http://testing.mainnet.beacon-api.nimbus.team"
	executionRpcUrl := "https://eth-mainnet.g.alchemy.com/v2/j28GcevSYukh-GvSeBOYcwHOfIggF1Gt"
	// strictCheckpointAge := false

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

	node, state, err := NewNode(config)
	if err != nil {
		fmt.Printf("Error in node creation: %v", err)
	}
	return node, state
}

// func main() {
// 	node, state := MakeNewNode()

// 	blockSendChan := node.Consensus.BlockRecv
// 	// finalizedBlockSend := node.Consensus.FinalizedBlockRecv
// 	client, err := rpc.Dial("https://eth-mainnet.g.alchemy.com/v2/j28GcevSYukh-GvSeBOYcwHOfIggF1Gt") // Replace with your RPC endpoint
//     if err != nil {
//         log.Fatalf("Failed to connect to the Ethereum node: %v", err)
//     }

// 	// Periodically fetch and update state with new blocks
//     go execution.FetchAndUpdateState(state, client, blockSendChan)
	
// 	go func() {
// 		block := state.GetBlock(seleneCommon.BlockTag{Latest: true})
// 		fmt.Printf("Block: %v\n", block)
// 		time.Sleep(1 * time.Second)
// 		number, err := node.GetBlockNumber()
// 		if err != nil {
// 			fmt.Printf("Error: %v", err)
// 		}
// 		fmt.Printf("BlockNumber: %d", number)
// 	}()
// 	// Run indefinitely (or until manually stopped)
//     select {}
// }

// func GetNewClient(strictCheckpointAge bool, sync bool) (*consensus.Inner, error) {
// 	var n config.Network
// 	baseConfig, err := n.BaseConfig("MAINNET")
// 	if err != nil {
// 		return nil, err
// 	}

// 	config := &config.Config{
// 		ConsensusRpc:        "",
// 		ExecutionRpc:        "",
// 		Chain:               baseConfig.Chain,
// 		Forks:               baseConfig.Forks,
// 		StrictCheckpointAge: strictCheckpointAge,
// 	}

// 	checkpoint := "b21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5"
// 	consensusRpcUrl := "http://testing.mainnet.beacon-api.nimbus.team"
// 	_ = "https://eth-mainnet.g.alchemy.com/v2/KLk2JrSPcjR8dp55N7XNTs9jeKTKHMoA"

// 	//Decode the hex string into a byte slice
// 	checkpointBytes, err := hex.DecodeString(checkpoint)
// 	checkpointBytes32 := [32]byte{}
// 	copy(checkpointBytes32[:], checkpointBytes)
// 	if err != nil {
// 		log.Fatalf("failed to decode checkpoint: %v", err)
// 	}

// 	blockSend := make(chan *seleneCommon.Block, 256)
// 	finalizedBlockSend := make(chan *seleneCommon.Block)
// 	channelSend := make(chan *[]byte)

// 	In := consensus.Inner{}
// 	client := In.New(
// 		consensusRpcUrl,
// 		blockSend,
// 		finalizedBlockSend,
// 		channelSend,
// 		config,
// 	)

// 	return client, nil
// }

// func TestNodeSyncing(t *testing.T) {
// 	node := MakeNewNode(t)
// 	// assert.Equal(t, Node{}, node, "Node didn't match expected")
// }

// func TestGetBalance(t *testing.T) {
// 	node := MakeNewNode(t)
// 	addressBytes, err := utils.Hex_str_to_bytes("0xB856af30B938B6f52e5BfF365675F358CD52F91B")
// 	assert.NoError(t, err, "Error in converting string to bytes")
// 	address := seleneCommon.Address{Addr: [20]byte(addressBytes)}
// 	blockTag := seleneCommon.BlockTag{Latest: true}

	
// 	balance, err := node.GetBalance(address, blockTag)

// 	assert.NoError(t, err, "Found error")
// 	assert.Equal(t, 0, balance, "Balance didn't match expected")
// }

func TestGetLogs(t *testing.T) {
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

	select{
	case logs := <- logsChan:
		assert.Equal(t, []types.Log{}, logs, "Logs didn't match expected")
	case err := <- errorChan:
		assert.NoError(t, err, "Found Error")
	}
}

// func TestGetBlockNumber(t *testing.T) {
// 	node := MakeNewNode(t)
// 	number, err := node.GetBlockNumber()
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, 0, number, "Number didn't match")
// }

// func TestStateUpdates(t *testing.T) {
// 	node, state := MakeNewNode(t)

// 	client, err := rpc.Dial("https://eth-mainnet.g.alchemy.com/v2/j28GcevSYukh-GvSeBOYcwHOfIggF1Gt") // Replace with your RPC endpoint
//     if err != nil {
//         log.Fatalf("Failed to connect to the Ethereum node: %v", err)
//     }

// 	// Periodically fetch and update state with new blocks
//     go execution.FetchAndUpdateState(state, client)
// 	fmt.Println("Reached Here")
// 	time.Sleep(5 * time.Second)
// 	number, err := node.GetBlockNumber()
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, 0, number, "Number didn't match")
//     // Run indefinitely (or until manually stopped)
//     select {}

// }