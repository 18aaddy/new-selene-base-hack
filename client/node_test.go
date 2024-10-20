package client

import (
	"log"
	"testing"

	"encoding/hex"

	seleneCommon "github.com/BlocSoc-iitr/selene/common"
	"github.com/BlocSoc-iitr/selene/config"
	"github.com/BlocSoc-iitr/selene/consensus"
	// "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func MakeNewNode() *Node {
	return &Node{}
}

func GetNewClient(strictCheckpointAge bool, sync bool) (*consensus.Inner, error) {
	var n config.Network
	baseConfig, err := n.BaseConfig("MAINNET")
	if err != nil {
		return nil, err
	}

	config := &config.Config{
		ConsensusRpc:        "",
		ExecutionRpc:        "",
		Chain:               baseConfig.Chain,
		Forks:               baseConfig.Forks,
		StrictCheckpointAge: strictCheckpointAge,
	}

	checkpoint := "b21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5"
	consensusRpcUrl := "http://testing.mainnet.beacon-api.nimbus.team"
	_ = "https://eth-mainnet.g.alchemy.com/v2/KLk2JrSPcjR8dp55N7XNTs9jeKTKHMoA"

	//Decode the hex string into a byte slice
	checkpointBytes, err := hex.DecodeString(checkpoint)
	checkpointBytes32 := [32]byte{}
	copy(checkpointBytes32[:], checkpointBytes)
	if err != nil {
		log.Fatalf("failed to decode checkpoint: %v", err)
	}

	blockSend := make(chan *seleneCommon.Block, 256)
	finalizedBlockSend := make(chan *seleneCommon.Block)
	channelSend := make(chan *[]byte)

	In := consensus.Inner{}
	client := In.New(
		consensusRpcUrl,
		blockSend,
		finalizedBlockSend,
		channelSend,
		config,
	)

	return client, nil
}

func TestNodeSyncing(t *testing.T) {
	var n config.Network
	baseConfig, err := n.BaseConfig("MAINNET")
	if err != nil {
		t.Errorf("Error in base config creation: %v", err)
	}

	checkpoint := "b21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5"
	consensusRpcUrl := "http://testing.mainnet.beacon-api.nimbus.team"
	executionRpcUrl := "https://eth-mainnet.g.alchemy.com/v2/KLk2JrSPcjR8dp55N7XNTs9jeKTKHMoA"
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

	node, err := NewNode(config)
	assert.NoError(t, err, "Found Error in New Node")
	assert.Equal(t, Node{}, node, "Node didn't match expected")
}

// func TestGetBalance(t *testing.T) {
// 	node := MakeNewNode()
// 	addressBytes := common.Hex2Bytes("")
// 	address := seleneCommon.Address{Addr: [20]byte(addressBytes)}
// 	blockTag := seleneCommon.BlockTag{}
// 	balance, err := node.GetBalance(address, blockTag)

// 	assert.NoError(t, err, "Found error")
// 	assert.Equal(t, 0, balance, "Balance didn't match expected")
// }

// func TestGetLogs(t *testing.T) {
// 	node := MakeNewNode()
// 	filter := ethereum.FilterQuery{}

// 	logs, err := node.GetLogs(&filter)
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, []types.Log{}, logs, "Logs didn't match expected")
// }

// func TestGetBlockNumber(t *testing.T) {
// 	node := MakeNewNode()
// 	number, err := node.GetBlockNumber()
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, 0, number, "Number didn't match")
// }
