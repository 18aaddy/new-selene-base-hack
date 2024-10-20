package client

import (
	"errors"
	"log"
	"math/big"
	"runtime"
	"time"

	seleneCommon "github.com/BlocSoc-iitr/selene/common"
	"github.com/BlocSoc-iitr/selene/config"
	"github.com/BlocSoc-iitr/selene/utils"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/BlocSoc-iitr/selene/consensus"
	"github.com/BlocSoc-iitr/selene/execution"
	"github.com/holiman/uint256"

	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"

	// "time"
	"encoding/json"
	// 	"fmt"
	// 	"log"
	// 	"math/big"
	"net"
	"net/http"
	"sync"

	// seleneCommon "github.com/BlocSoc-iitr/selene/common"
	// "github.com/ethereum/go-ethereum"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/sirupsen/logrus"
)
type ClientBuilder struct {
	Network              *config.Network
	ConsensusRpc         *string
	ExecutionRpc         *string
	Checkpoint           *[32]byte
	//If architecture is Web Assembly (wasm32), this will be nil
	RpcBindIp            *string
	//If architecture is Web Assembly (wasm32), this will be nil
	RpcPort              *uint16
	//If architecture is Web Assembly (wasm32), this will be nil
	DataDir              *string
	Config               *config.Config
	Fallback             *string
	LoadExternalFallback bool
	StrictCheckpointAge  bool
}
func (c Client) Build(b ClientBuilder) (*Client, error) {
	var baseConfig config.BaseConfig
	var err error
	_ = err
	if b.Network != nil {
		baseConfig, err = b.Network.BaseConfig(string(*b.Network))
		if err != nil {
			return nil, errors.Join(errors.New("error in base config"), err)
		}
	} else {
		if b.Config == nil {
			return nil, errors.New("missing network config")
		}
		baseConfig = b.Config.ToBaseConfig()
	}
	consensusRPC := b.ConsensusRpc
	if consensusRPC == nil {
		if b.Config == nil {
			return nil, errors.New("missing consensus rpc")
		}
		consensusRPC = &b.Config.ConsensusRpc
	}
	executionRPC := b.ExecutionRpc
	if executionRPC == nil {
		if b.Config == nil {
			return nil, errors.New("missing execution rpc")
		}
		executionRPC = &b.Config.ExecutionRpc
	}
	checkpoint := b.Checkpoint
	if checkpoint == nil {
		if b.Config != nil {
			checkpoint = b.Config.Checkpoint
		}
	}
	var defaultCheckpoint [32]byte
	if b.Config != nil {
		defaultCheckpoint = b.Config.DefaultCheckpoint
	} else {
		defaultCheckpoint = baseConfig.DefaultCheckpoint
	}
	var rpcBindIP, dataDir *string
	var rpcPort *uint16
	if runtime.GOARCH == "wasm" {
		rpcBindIP = nil
	} else {
		if b.RpcBindIp != nil {
			rpcBindIP = b.RpcBindIp
		} else if b.Config != nil {
			rpcBindIP = b.Config.RpcBindIp
		}
	}
	if runtime.GOARCH == "wasm" {
		rpcPort = nil
	} else {
		if b.RpcPort != nil {
			rpcPort = b.RpcPort
		} else if b.Config != nil {
			rpcPort = b.Config.RpcPort
		}
	}
	if runtime.GOARCH == "wasm" {
		dataDir = nil
	} else {
		if b.DataDir != nil {
			dataDir = b.DataDir
		} else if b.Config != nil {
			dataDir = b.Config.DataDir
		}
	}
	fallback := b.Fallback
	if fallback == nil && b.Config != nil {
		fallback = b.Config.Fallback
	}
	loadExternalFallback := b.LoadExternalFallback
	if b.Config != nil {
		loadExternalFallback = loadExternalFallback || b.Config.LoadExternalFallback
	}
	strictCheckpointAge := b.StrictCheckpointAge
	if b.Config != nil {
		strictCheckpointAge = strictCheckpointAge || b.Config.StrictCheckpointAge
	}
	config := config.Config{
		ConsensusRpc:         *consensusRPC,
		ExecutionRpc:         *executionRPC,
		Checkpoint:           checkpoint,
		DefaultCheckpoint:    defaultCheckpoint,
		RpcBindIp:            rpcBindIP,
		RpcPort:              rpcPort,
		DataDir:              dataDir,
		Chain:                baseConfig.Chain,
		Forks:                baseConfig.Forks,
		MaxCheckpointAge:     baseConfig.MaxCheckpointAge,
		Fallback:             fallback,
		LoadExternalFallback: loadExternalFallback,
		StrictCheckpointAge:  strictCheckpointAge,
		DatabaseType:         nil,
	}
	client, err := Client{}.New(config)
	if err != nil {
		return nil, errors.Join(errors.New("error in client creation"), err)
	}
	return &client, nil
}
type Client struct {
	Node *Node
	Rpc  *Rpc
}
func (c Client) New(clientConfig config.Config) (Client, error) {
	config := &clientConfig
	node,_, err := NewNode(config)
	var rpc Rpc
	if err != nil {
		return Client{}, err
	}
	if config.RpcBindIp != nil || config.RpcPort != nil {
		rpc = Rpc{}.New(node, config.RpcBindIp, *config.RpcPort)
	}
	return Client{
		Node: node,
		Rpc: func() *Rpc {
			if runtime.GOARCH == "wasm" {
				return nil
			} else {
				return &rpc
			}
		}(),
	}, nil
}
func (c *Client) Start() error {
	errorChan := make(chan error, 1)
	go func() {
		defer close(errorChan)
		if runtime.GOARCH != "wasm" {
			if c.Rpc == nil {
				errorChan <- errors.New("Rpc not found")
				return
			}
			_, err := c.Rpc.Start()
			if err != nil {
				errorChan <- err
				return
			}
		}
		errorChan <- nil
	}()
	err := <-errorChan
	return err
}
func (c *Client) Shutdown() {
	log.Println("selene::client - shutting down")
	go func() {
		err := c.Node.Consensus.Shutdown()
		if err != nil {
			log.Printf("selene::client - graceful shutdown failed: %v\n", err)
		}
	}()
}
// func (c *Client) Call(tx *TransactionRequest, block seleneCommon.BlockTag) ([]byte, error) {
// 	resultChan := make(chan []byte, 1)
// 	errorChan := make(chan error, 1)
// 	go func() {
// 		defer close(resultChan)
// 		defer close(errorChan)
// 		result, err := c.Node.Call(tx, block)
// 		if err != nil {
// 			errorChan <- err
// 		} else {
// 			resultChan <- result
// 		}
// 	}()
// 	select {
// 	case result := <-resultChan:
// 		return result, nil
// 	case err := <-errorChan:
// 		return nil, err
// 	}
// }
// func (c *Client) EstimateGas(tx *TransactionRequest) (uint64, error) {
// 	resultChan := make(chan uint64, 1)
// 	errorChan := make(chan error, 1)
// 	go func() {
// 		defer close(resultChan)
// 		defer close(errorChan)
// 		result, err := c.Node.EstimateGas(tx)
// 		if err != nil {
// 			errorChan <- err
// 		} else {
// 			resultChan <- result
// 		}
// 	}()
// 	select {
// 	case result := <-resultChan:
// 		return result, nil
// 	case err := <-errorChan:
// 		return 0, err
// 	}
// }
func (c *Client) GetBalance(address seleneCommon.Address, block seleneCommon.BlockTag) (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBalance(address, block)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetNonce(address seleneCommon.Address, block seleneCommon.BlockTag) (uint64, error) {
	resultChan := make(chan uint64, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetNonce(address, block)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return 0, err
	}
}
func (c *Client) GetBlockTransactionCountByHash(hash [32]byte) (uint64, error) {
	resultChan := make(chan uint64, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBlockTransactionCountByHash(hash)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return 0, err
	}
}
func (c *Client) GetBlockTransactionCountByNumber(block seleneCommon.BlockTag) (uint64, error) {
	resultChan := make(chan uint64, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBlockTransactionCountByNumber(block)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return 0, err
	}
}
func (c *Client) GetCode(address seleneCommon.Address, block seleneCommon.BlockTag) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetCode(address, block)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetStorageAt(address seleneCommon.Address, slot [32]byte, block seleneCommon.BlockTag) (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetStorageAt(address, slot, block)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) SendRawTransaction(bytes *[]byte) ([32]byte, error) {
	resultChan := make(chan [32]byte, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.SendRawTransaction(*bytes)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return [32]byte{}, err
	}
}
func (c *Client) GetTransactionReceipt(txHash [32]byte) (*types.Receipt, error) {
	resultChan := make(chan *types.Receipt, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetTransactionReceipt(txHash)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetTransactionByHash(txHash [32]byte) (*seleneCommon.Transaction, error) {
	resultChan := make(chan *seleneCommon.Transaction, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetTransactionByHash(txHash)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetLogs(filter *ethereum.FilterQuery) ([]types.Log, error) {
	resultChan := make(chan []types.Log, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetLogs(filter)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetFilterChanges(filterId *big.Int) ([]types.Log, error) {
	resultChan := make(chan []types.Log, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetFilterChanges(filterId)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) UninstallFilter(filterId *big.Int) (bool, error) {
	resultChan := make(chan bool, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.UninstallFilter(filterId)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return false, err
	}
}
func (c *Client) GetNewFilter(filter *ethereum.FilterQuery) (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetNewFilter(filter)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetNewBlockFilter() (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetNewBlockFilter()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetNewPendingTransactionFilter() (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetNewPendingTransactionFilter()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetGasPrice() (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetGasPrice()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetPriorityFee() *big.Int {
	return c.Node.GetPriorityFee()
}
func (c *Client) GetBlockNumber() (*big.Int, error) {
	resultChan := make(chan *big.Int, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBlockNumber()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetBlockByNumber(block seleneCommon.BlockTag, fullTx bool) (*seleneCommon.Block, error) {
	resultChan := make(chan *seleneCommon.Block, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBlockByNumber(block, fullTx)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- &result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetBlockByHash(hash [32]byte, fullTx bool) (*seleneCommon.Block, error) {
	resultChan := make(chan *seleneCommon.Block, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetBlockByHash(hash, fullTx)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- &result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetTransactionByBlockHashAndIndex(blockHash [32]byte, index uint64) (*seleneCommon.Transaction, error) {
	resultChan := make(chan *seleneCommon.Transaction, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetTransactionByBlockHashAndIndex(blockHash, index)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) ChainID() uint64 {
	return c.Node.ChainId()
}
func (c *Client) Syncing() (*SyncStatus, error) {
	resultChan := make(chan *SyncStatus, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.Syncing()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- &result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}
func (c *Client) GetCoinbase() ([20]byte, error) {
	resultChan := make(chan [20]byte, 1)
	errorChan := make(chan error, 1)
	go func() {
		defer close(resultChan)
		defer close(errorChan)
		result, err := c.Node.GetCoinbase()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return [20]byte{}, err
	}
}
func (c *Client) WaitSynced() error {
	for {
		statusChan := make(chan *SyncStatus)
		errChan := make(chan error)
		go func() {
			status, err := c.Syncing()
			if err != nil {
				errChan <- err
			} else {
				statusChan <- status
			}
		}()
		select {
		case status := <-statusChan:
			if status.Status == "None" {
				return nil
			}
		case err := <-errChan:
			return err
		case <-time.After(100 * time.Millisecond):
			// Periodic checking of SyncStatus or error
		}
	}
}

// package client

// import (
// 	"errors"
// 	"math/big"
// 	"time"

// 	seleneCommon "github.com/BlocSoc-iitr/selene/seleneCommon"
// 	"github.com/BlocSoc-iitr/selene/config"
// 	"github.com/BlocSoc-iitr/selene/consensus"
// 	"github.com/BlocSoc-iitr/selene/execution"
// 	"github.com/ethereum/go-ethereum"
// 	"github.com/ethereum/go-ethereum/seleneCommon"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/holiman/uint256"
// )

// Used instead of Alloy::TransactionRequest
type TransactionRequest struct {
	From     string
	To       string
	Value    *big.Int
	Gas      uint64
	GasPrice *big.Int
	Data     []byte
}

// Here [32]byte is used for B256 type in Rust and *big.Int is used for U256 type
type Node struct {
	Consensus   *consensus.ConsensusClient
	Execution   *execution.ExecutionClient
	Config      *config.Config
	HistorySize int
}

func NewNode(config *config.Config) (*Node, *execution.State, error) {
	consensusRPC := config.ConsensusRpc
	executionRPC := config.ExecutionRpc
	// Initialize ConsensusClient
	consensus := consensus.ConsensusClient{}.New(&consensusRPC, *config)
	// Extract block receivers
	blockRecv := consensus.BlockRecv
	if blockRecv == nil {
		return nil, nil, errors.New("blockRecv is nil")
	}
	finalizedBlockRecv := consensus.FinalizedBlockRecv
	if finalizedBlockRecv == nil {
		return nil, nil, errors.New("finalizedBlockRecv is nil")
	}
	// Initialize State
	state := execution.NewState(256, blockRecv, finalizedBlockRecv)
	// Initialize ExecutionClient
	execution, err := (&execution.ExecutionClient{}).New(executionRPC, state)
	if err != nil {
		return nil, nil, errors.New("ExecutionClient creation error")
	}
	// Return the constructed Node
	return &Node{
		Consensus:   &consensus,
		Execution:   execution,
		Config:      config,
		HistorySize: 64,
	}, state, nil
}

// func (n *Node) Call(tx *TransactionRequest, block seleneCommon.BlockTag) ([]byte, *NodeError) {
//     resultChan := make(chan []byte)
//     errorChan := make(chan *NodeError)

//     go func() {
//         n.CheckBlocktagAge(block)
//         evm := (&execution.Evm{}).New(n.Execution, n.ChainId, block)
//         result, err := evm.Call(tx)
//         if err != nil {
//             errorChan <- NewExecutionClientCreationError(err)
//             return
//         }
//         resultChan <- result
//         errorChan <- nil
//     }()

//     select {
//     case result := <-resultChan:
//         return result, nil
//     case err := <-errorChan:
//         return nil, err
//     }
// }

// func (n *Node) EstimateGas(tx *TransactionRequest) (uint64, *NodeError) {
//     resultChan := make(chan uint64)
//     errorChan := make(chan *NodeError)

//     go func() {
//         n.CheckHeadAge()
//         evm := (&execution.Evm{}).New(n.Execution, n.ChainId, seleneCommon.BlockTag{Latest: true})
//         result, err := evm.EstimateGas(tx)
//         if err != nil {
//             errorChan <- NewExecutionEvmError(err)
//             return
//         }
//         resultChan <- result
//         errorChan <- nil
//     }()

//     select {
//     case result := <-resultChan:
//         return result, nil
//     case err := <-errorChan:
//         return 0, err
//     }
// }

func (n *Node) GetBalance(address seleneCommon.Address, tag seleneCommon.BlockTag) (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        n.CheckBlocktagAge(tag)
        account, err := n.Execution.GetAccount(&address, nil, tag)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- account.Balance
        errorChan <- nil
    }()

    select {
    case balance := <-resultChan:
        return balance, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetNonce(address seleneCommon.Address, tag seleneCommon.BlockTag) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        n.CheckBlocktagAge(tag)
        account, err := n.Execution.GetAccount(&address, nil, tag)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- account.Nonce
        errorChan <- nil
    }()

    select {
    case nonce := <-resultChan:
        return nonce, nil
    case err := <-errorChan:
        return 0, err
    }
}

func (n *Node) GetBlockTransactionCountByHash(hash [32]byte) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        block, err := n.Execution.GetBlockByHash(hash, false)
        if err != nil {
            errorChan <- err
            return
        }
        transactionCount := len(block.Transactions.HashesFunc())
        resultChan <- uint64(transactionCount)
        errorChan <- nil
    }()

    select {
    case txCount := <-resultChan:
        return txCount, nil
    case err := <-errorChan:
        return 0, err
    }
}

func (n *Node) GetBlockTransactionCountByNumber(tag seleneCommon.BlockTag) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        block, err := n.Execution.GetBlock(tag, false)
        if err != nil {
            errorChan <- err
            return
        }
        transactionCount := len(block.Transactions.HashesFunc())
        resultChan <- uint64(transactionCount)
        errorChan <- nil
    }()

    select {
    case txCount := <-resultChan:
        return txCount, nil
    case err := <-errorChan:
        return 0, err
    }
}

func (n *Node) GetCode(address seleneCommon.Address, tag seleneCommon.BlockTag) ([]byte, error) {
    resultChan := make(chan []byte)
    errorChan := make(chan error)

    go func() {
        n.CheckBlocktagAge(tag)
        account, err := n.Execution.GetAccount(&address, nil, tag)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- account.Code
        errorChan <- nil
    }()

    select {
    case code := <-resultChan:
        return code, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetStorageAt(address seleneCommon.Address, slot common.Hash, tag seleneCommon.BlockTag) (*big.Int, error) {
	resultChan := make(chan *big.Int)
	errorChan := make(chan error)

	go func() {
		n.CheckHeadAge()
		account, err := n.Execution.GetAccount(&address, nil, tag)
		if err != nil {
			errorChan <- err
			return
		}
		value := func() *big.Int {for _, s := range account.Slots { // Loop through all slots
				if s.Key == slot {
					return s.Value // Return the value if the key matches
				}
			}
			return nil
		}()
		if value == nil {
			resultChan <- nil
			errorChan <- errors.New("slot not found")
			return
		}
		resultChan <- value
		errorChan <- nil
	}()

	return <-resultChan, <-errorChan
}

func (n *Node) SendRawTransaction(bytes []byte) ([32]byte, error) {
    resultChan := make(chan [32]byte)
    errorChan := make(chan error)

    go func() {
        txHash, err := n.Execution.SendRawTransaction(bytes)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txHash
        errorChan <- nil
    }()

    select {
    case txHash := <-resultChan:
        return txHash, nil
    case err := <-errorChan:
        return [32]byte{}, err
    }
}

func (n *Node) GetTransactionReceipt(txHash [32]byte) (*types.Receipt, error) {
    resultChan := make(chan *types.Receipt)
    errorChan := make(chan error)

    go func() {
        txnReceipt, err := n.Execution.GetTransactionReceipt(txHash)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- &txnReceipt
        errorChan <- nil
    }()

    select {
    case receipt := <-resultChan:
        return receipt, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetTransactionByHash(txHash [32]byte) (*seleneCommon.Transaction, error) {
    resultChan := make(chan *seleneCommon.Transaction)
    errorChan := make(chan error)

    go func() {
        txn, err := n.Execution.GetTransaction(txHash)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- &txn
        errorChan <- nil
    }()

    select {
    case txn := <-resultChan:
        return txn, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetTransactionByBlockHashAndIndex(hash [32]byte, index uint64) (*seleneCommon.Transaction, error) {
    resultChan := make(chan *seleneCommon.Transaction)
    errorChan := make(chan error)

    go func() {
        txn, err := n.Execution.GetTransactionByBlockHashAndIndex(hash, index)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- &txn
        errorChan <- nil
    }()

    select {
    case txn := <-resultChan:
        return txn, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetLogs(filter *ethereum.FilterQuery) ([]types.Log, error) {
    resultChan := make(chan []types.Log)
    errorChan := make(chan error)

    go func() {
        logs, err := n.Execution.GetLogs(*filter)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- logs
        errorChan <- nil
    }()

    select {
    case logs := <-resultChan:
        return logs, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetFilterChanges(filterId *big.Int) ([]types.Log, error) {
    resultChan := make(chan []types.Log)
    errorChan := make(chan error)

    go func() {
        logs, err := n.Execution.GetFilterChanges(uint256.MustFromBig(filterId))
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- logs
        errorChan <- nil
    }()

    select {
    case logs := <-resultChan:
        return logs, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) UninstallFilter(filterId *big.Int) (bool, error) {
    resultChan := make(chan bool)
    errorChan := make(chan error)

    go func() {
        success, err := n.Execution.UninstallFilter(uint256.MustFromBig(filterId))
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- success
        errorChan <- nil
    }()

    select {
    case success := <-resultChan:
        return success, nil
    case err := <-errorChan:
        return false, err
    }
}

func (n *Node) GetNewFilter(filter *ethereum.FilterQuery) (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := n.Execution.GetNewFilter(*filter)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId.ToBig()
        errorChan <- nil
    }()

    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetNewBlockFilter() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := n.Execution.GetNewBlockFilter()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId.ToBig()
        errorChan <- nil
    }()

    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetNewPendingTransactionFilter() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := n.Execution.GetNewPendingTransactionFilter()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId.ToBig()
        errorChan <- nil
    }()

    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetGasPrice() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        n.CheckHeadAge()
        block, err := n.Execution.GetBlock(seleneCommon.BlockTag{Latest: true}, false)
        if err != nil {
            errorChan <- err
            return
        }
        baseFee := block.BaseFeePerGas
        tip := new(big.Int).Exp(big.NewInt(10), big.NewInt(9), nil)  // 1 Gwei
        resultChan <- new(big.Int).Add(baseFee.ToBig(), tip)
        errorChan <- nil
    }()

    select {
    case gasPrice := <-resultChan:
        return gasPrice, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetPriorityFee() *big.Int {
	tip := new(big.Int).Exp(big.NewInt(10), big.NewInt(9), nil)
	return tip
}

func (n *Node) GetBlockNumber() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        n.CheckHeadAge()
        block, err := n.Execution.GetBlock(seleneCommon.BlockTag{Latest: true}, false)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- big.NewInt(int64(block.Number))
        errorChan <- nil
    }()

    select {
    case blockNumber := <-resultChan:
        return blockNumber, nil
    case err := <-errorChan:
        return nil, err
    }
}

func (n *Node) GetBlockByNumber(tag seleneCommon.BlockTag, fullTx bool) (seleneCommon.Block, error) {
    resultChan := make(chan seleneCommon.Block)
    errorChan := make(chan error)

    go func() {
        n.CheckBlocktagAge(tag)
        block, err := n.Execution.GetBlock(tag, fullTx)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- block
        errorChan <- nil
    }()

    select {
    case block := <-resultChan:
        return block, nil
    case err := <-errorChan:
        return seleneCommon.Block{}, err
    }
}

func (n *Node) GetBlockByHash(hash [32]byte, fullTx bool) (seleneCommon.Block, error) {
    resultChan := make(chan seleneCommon.Block)
    errorChan := make(chan error)

    go func() {
        block, err := n.Execution.GetBlockByHash(hash, fullTx)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- block
        errorChan <- nil
    }()

    select {
    case block := <-resultChan:
        return block, nil
    case err := <-errorChan:
        return seleneCommon.Block{}, err
    }
}

func (n *Node) ChainId() uint64 {
	return n.Config.Chain.ChainID
}

type SyncInfo struct {
	CurrentBlock  *big.Int
	HighestBlock  *big.Int
	StartingBlock *big.Int
}
type SyncStatus struct {
	Status string
	Info   SyncInfo
}

func (n *Node) Syncing() (SyncStatus, error) {
    resultChan := make(chan SyncStatus)
    errorChan := make(chan error)

    go func() {
        headErrChan := make(chan error)
        blockNumberChan := make(chan *big.Int)
        highestBlockChan := make(chan uint64)

        go func() {
            headErrChan <- n.CheckHeadAge()
        }()

        go func() {
            blockNumber, err := n.GetBlockNumber()
            if err != nil {
                blockNumberChan <- big.NewInt(0)
            } else {
                blockNumberChan <- blockNumber
            }
        }()

        go func() {
            highestBlock := n.Consensus.Expected_current_slot()
            highestBlockChan <- highestBlock
        }()
        headErr := <-headErrChan
        if headErr == nil {
            resultChan <- SyncStatus{
                Status: "None",
            }
            errorChan <- nil
            return
        }
        latestSyncedBlock := <-blockNumberChan
        highestBlock := <-highestBlockChan

        resultChan <- SyncStatus{
            Info: SyncInfo{
                CurrentBlock:  latestSyncedBlock,
                HighestBlock:  big.NewInt(int64(highestBlock)),
                StartingBlock: big.NewInt(0),
            },
        }
        errorChan <- headErr
    }()

    select {
    case result := <-resultChan:
        return result, nil
    case err := <-errorChan:
        return SyncStatus{}, err
    }
}

func (n *Node) GetCoinbase() ([20]byte, error) {
    resultChan := make(chan [20]byte)
    errorChan := make(chan error)

    go func() {
        headErrChan := make(chan error)
        blockChan := make(chan *seleneCommon.Block)

        go func() {
            headErrChan <- n.CheckHeadAge()
        }()

        go func() {
            block, err := n.Execution.GetBlock(seleneCommon.BlockTag{Latest: true}, false)
            if err != nil {
                errorChan <- err
                resultChan <- [20]byte{}
                return
            }
            blockChan <- &block
        }()

        if headErr := <-headErrChan; headErr != nil {
            resultChan <- [20]byte{}
            errorChan <- headErr
            return
        }

        block := <-blockChan
        resultChan <- block.Miner.Addr
        errorChan <- nil
    }()

    select {
    case coinbase := <-resultChan:
        return coinbase, nil
    case err := <-errorChan:
        return [20]byte{}, err
    }
}

func (n *Node) CheckHeadAge() *NodeError {
    resultChan := make(chan *NodeError)

    go func() {
        currentTime := time.Now()
        currentTimestamp := uint64(currentTime.Unix())

        block, err := n.Execution.GetBlock(seleneCommon.BlockTag{Latest: true}, false)
        if err != nil {
            resultChan <- &NodeError{}
            return
        }
        blockTimestamp := block.Timestamp
        delay := currentTimestamp - blockTimestamp
        if delay > 60 {
            resultChan <- NewOutOfSyncError(time.Duration(delay) * time.Second)
            return
        }

        resultChan <- nil
    }()

    return <-resultChan
}

func (n *Node) CheckBlocktagAge(block seleneCommon.BlockTag) *NodeError {
    errorChan := make(chan *NodeError)

    go func() {
        if block.Latest {
            headErr := n.CheckHeadAge()
            errorChan <- headErr
            return
        }
        if block.Finalized {
            errorChan <- nil
            return
        }
        errorChan <- nil
    }()
    return <-errorChan
}

// package client

// import (
// 	"fmt"
// 	"github.com/ethereum/go-ethereum/common/hexutil"
// 	"time"
// )

// NodeError is the base error type for all node-related errors
type NodeError struct {
	errType string
	message string
	cause   error
}

func (e *NodeError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s", e.errType, e.cause.Error())
	}
	return fmt.Sprintf("%s: %s", e.errType, e.message)
}
func (e *NodeError) Unwrap() error {
	return e.cause
}

// NewExecutionEvmError creates a new ExecutionEvmError
func NewExecutionEvmError(err error) *NodeError {
	return &NodeError{
		errType: "ExecutionEvmError",
		cause:   err,
	}
}

// NewExecutionError creates a new ExecutionError
func NewExecutionError(err error) *NodeError {
	return &NodeError{
		errType: "ExecutionError",
		message: "execution error",
		cause:   err,
	}
}

// NewOutOfSyncError creates a new OutOfSyncError
func NewOutOfSyncError(behind time.Duration) *NodeError {
	return &NodeError{
		errType: "OutOfSyncError",
		message: fmt.Sprintf("out of sync: %s behind", behind),
	}
}

// NewConsensusPayloadError creates a new ConsensusPayloadError
func NewConsensusPayloadError(err error) *NodeError {
	return &NodeError{
		errType: "ConsensusPayloadError",
		message: "consensus payload error",
		cause:   err,
	}
}

// NewExecutionPayloadError creates a new ExecutionPayloadError
func NewExecutionPayloadError(err error) *NodeError {
	return &NodeError{
		errType: "ExecutionPayloadError",
		message: "execution payload error",
		cause:   err,
	}
}

// NewConsensusClientCreationError creates a new ConsensusClientCreationError
func NewConsensusClientCreationError(err error) *NodeError {
	return &NodeError{
		errType: "ConsensusClientCreationError",
		message: "consensus client creation error",
		cause:   err,
	}
}

// NewExecutionClientCreationError creates a new ExecutionClientCreationError
func NewExecutionClientCreationError(err error) *NodeError {
	return &NodeError{
		errType: "ExecutionClientCreationError",
		message: "execution client creation error",
		cause:   err,
	}
}

// NewConsensusAdvanceError creates a new ConsensusAdvanceError
func NewConsensusAdvanceError(err error) *NodeError {
	return &NodeError{
		errType: "ConsensusAdvanceError",
		message: "consensus advance error",
		cause:   err,
	}
}

// NewConsensusSyncError creates a new ConsensusSyncError
func NewConsensusSyncError(err error) *NodeError {
	return &NodeError{
		errType: "ConsensusSyncError",
		message: "consensus sync error",
		cause:   err,
	}
}

// NewBlockNotFoundError creates a new BlockNotFoundError
func NewBlockNotFoundError(err error) *NodeError {
	return &NodeError{
		errType: "BlockNotFoundError",
		cause:   err,
	}
}

// EvmError represents errors from the EVM
type EvmError struct {
	revertData []byte
}

func (e *EvmError) Error() string {
	return "EVM error"
}

// DecodeRevertReason attempts to decode the revert reason from the given data
func DecodeRevertReason(data []byte) string {
	// This is a placeholder. In a real implementation, you'd decode the ABI-encoded revert reason.
	return string(data)
}

// JSONRPCError represents a JSON-RPC error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ToJSONRPCError converts a NodeError to a JSON-RPC error
func (e *NodeError) ToJSONRPCError() *JSONRPCError {
	switch e.errType {
	case "ExecutionEvmError":
		if evmErr, ok := e.cause.(*EvmError); ok {
			if evmErr.revertData != nil {
				msg := "execution reverted"
				if reason := DecodeRevertReason(evmErr.revertData); reason != "" {
					msg = fmt.Sprintf("%s: %s", msg, reason)
				}
				return &JSONRPCError{
					Code:    3, // Assuming 3 is the code for execution revert
					Message: msg,
					Data:    hexutil.Encode(evmErr.revertData),
				}
			}
		}
		return &JSONRPCError{
			Code:    -32000, // Generic server error
			Message: e.Error(),
		}
	default:
		return &JSONRPCError{
			Code:    -32000, // Generic server error
			Message: e.Error(),
		}
	}
}

// package client

// import (
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"math/big"
// 	"net"
// 	"net/http"
// 	"sync"

// 	seleneCommon "github.com/BlocSoc-iitr/selene/common"
// 	"github.com/ethereum/go-ethereum"
// 	// "github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/sirupsen/logrus"
// )

type Rpc struct {
	Node    *Node
	Handle  *Server
	Address string
}

func (r Rpc) New(node *Node, ip *string, port uint16) Rpc {
	var address string
	if ip == nil {
		address = "127.0.0.1:8545"
	} else {
		address = fmt.Sprintf("%s:%d", *ip, port)
	}
	return Rpc{
		Node:    node,
		Handle:  nil,
		Address: address,
	}
}

func (r Rpc) Start() (string, error) {
    // Create channels to send the address and error back asynchronously
    addrChan := make(chan string)
    errChan := make(chan error)

    // Run the function in a separate goroutine
    go func() {
        rpcInner := RpcInner{
            Node:    r.Node,
            Address: r.Address,
        }
        handle, addr, err := rpcInner.StartServer()
        if err != nil {
            // Send the error on the error channel and close the channels
            errChan <- err
            close(addrChan)
            close(errChan)
            return
        }
        r.Handle = handle
        logrus.WithField("target", "selene::rpc").Infof("rpc server started at %s", addr)

        // Send the address on the address channel and close the channels
        addrChan <- addr
        close(addrChan)
        close(errChan)
    }()

    return <-addrChan, <-errChan
}

type RpcInner struct {
	Node    *Node
	Address string
}

func (r *RpcInner) GetBalance(address seleneCommon.Address, block seleneCommon.BlockTag) (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)
    go func() {
        balance, err := r.Node.GetBalance(address, block)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- balance
    }()
    select {
    case balance := <-resultChan:
        return balance, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetTransactionCount(address seleneCommon.Address, block seleneCommon.BlockTag) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        txCount, err := r.Node.GetNonce(address, block)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- uint64(txCount)
    }()
    select {
    case txCount := <-resultChan:
        return txCount, nil
    case err := <-errorChan:
        return 0, err
    }
}
func (r *RpcInner) GetBlockTransactionCountByHash(hash [32]byte) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        txCount, err := r.Node.GetBlockTransactionCountByHash(hash)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txCount
    }()
    select {
    case txCount := <-resultChan:
        return txCount, nil
    case err := <-errorChan:
        return 0, err
    }
}
func (r *RpcInner) GetBlockTransactionCountByNumber(block seleneCommon.BlockTag) (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        txCount, err := r.Node.GetBlockTransactionCountByNumber(block)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txCount
 
	}()
    select {
    case txCount := <-resultChan:
        return txCount, nil
    case err := <-errorChan:
        return 0, err
    }
}
func (r *RpcInner) GetCode(address seleneCommon.Address, block seleneCommon.BlockTag) ([]byte, error) {
    resultChan := make(chan []byte)
    errorChan := make(chan error)

    go func() {
        code, err := r.Node.GetCode(address, block)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- code
    	}()
    select {
    case code := <-resultChan:
        return code, nil
    case err := <-errorChan:
        return nil, err
    }
}
// func (r *RpcInner) Call(tx TransactionRequest, block seleneCommon.BlockTag) ([]byte, error) {
//     resultChan := make(chan []byte)
//     errorChan := make(chan error)
 
// 	go func() {
//         result, err := r.Node.Call(&tx, block)
//         if err != nil {
//             errorChan <- err.cause
//             return
//         }
//         resultChan <- result
    
// 		}()
//     select {
//     case result := <-resultChan:
//         return result, nil
//     case err := <-errorChan:
//         return nil, err
//     }
// }
// func (r *RpcInner) EstimateGas(tx *TransactionRequest) (uint64, error) {
//     resultChan := make(chan uint64)
//     errorChan := make(chan error)
//     go func() {
//         gas, err := r.Node.EstimateGas(tx)
//         if err != nil {
//             errorChan <- err.cause
//             return
//         }
//         resultChan <- gas
//     }()
//     select {
//     case gas := <-resultChan:
//         return gas, nil
//     case err := <-errorChan:
//         return 0, err
//     }
// }
func (r *RpcInner) ChainId() (uint64, error) {
	return r.Node.ChainId(), nil
}
func (r *RpcInner) GasPrice() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        gasPrice, err := r.Node.GetGasPrice()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- gasPrice
    }()

    select {
    case gasPrice := <-resultChan:
        return gasPrice, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) MaxPriorityFeePerGas() *big.Int {
	return r.Node.GetPriorityFee()
}
func (r *RpcInner) BlockNumber() (uint64, error) {
    resultChan := make(chan uint64)
    errorChan := make(chan error)

    go func() {
        number, err := r.Node.GetBlockNumber()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- number.Uint64()
    }()

    select {
    case number := <-resultChan:
        return number, nil
    case err := <-errorChan:
        return 0, err
    }
}
func (r *RpcInner) GetBlockByNumber(blockTag seleneCommon.BlockTag, fullTx bool) (*seleneCommon.Block, error) {
    resultChan := make(chan *seleneCommon.Block)
    errorChan := make(chan error)

    go func() {
        block, err := r.Node.GetBlockByNumber(blockTag, fullTx)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- &block
    }()

    select {
    case block := <-resultChan:
        return block, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetBlockByHash(hash [32]byte, fullTx bool) (*seleneCommon.Block, error) {
    resultChan := make(chan *seleneCommon.Block)
    errorChan := make(chan error)

    go func() {
        block, err := r.Node.GetBlockByHash(hash, fullTx)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- &block
    }()

    select {
    case block := <-resultChan:
        return block, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) SendRawTransaction(bytes []byte) ([32]byte, error) {
    resultChan := make(chan [32]byte)
    errorChan := make(chan error)

    go func() {
        hash, err := r.Node.SendRawTransaction(bytes)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- hash
    }()

    select {
    case hash := <-resultChan:
        return hash, nil
    case err := <-errorChan:
        return [32]byte{}, err
    }
}
func (r *RpcInner) GetTransactionReceipt(hash [32]byte) (*types.Receipt, error) {
    resultChan := make(chan *types.Receipt)
    errorChan := make(chan error)

    go func() {
        txnReceipt, err := r.Node.GetTransactionReceipt(hash)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txnReceipt
    }()

    select {
    case txnReceipt := <-resultChan:
        return txnReceipt, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetTransactionByHash(hash [32]byte) (*seleneCommon.Transaction, error) {
    resultChan := make(chan *seleneCommon.Transaction)
    errorChan := make(chan error)

    go func() {
        txn, err := r.Node.GetTransactionByHash(hash)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txn
    }()

    select {
    case txn := <-resultChan:
        return txn, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetTransactionByBlockHashAndIndex(hash [32]byte, index uint64) (*seleneCommon.Transaction, error) {
    resultChan := make(chan *seleneCommon.Transaction)
    errorChan := make(chan error)

    go func() {
        txn, err := r.Node.GetTransactionByBlockHashAndIndex(hash, index)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- txn
    }()

    select {
    case txn := <-resultChan:
        return txn, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) Coinbase() ([20]byte, error) {
    resultChan := make(chan [20]byte)
    errorChan := make(chan error)

    go func() {
        coinbase, err := r.Node.GetCoinbase()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- coinbase
    }()

    select {
    case coinbase := <-resultChan:
        return coinbase, nil
    case err := <-errorChan:
        return [20]byte{}, err
    }
}
func (r *RpcInner) Syncing() (SyncStatus, error) {
    resultChan := make(chan SyncStatus)
    errorChan := make(chan error)

    go func() {
        sync, err := r.Node.Syncing()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- sync
    }()
    select {
    case sync := <-resultChan:
        return sync, nil
    case err := <-errorChan:
        return SyncStatus{}, err
    }
}
func (r *RpcInner) GetLogs(filter ethereum.FilterQuery) ([]types.Log, error) {
    resultChan := make(chan []types.Log)
    errorChan := make(chan error)

    go func() {
        logs, err := r.Node.GetLogs(&filter)
	    if err != nil {
            errorChan <- err
            return
        }
        resultChan <- logs
    }()
    select {
    case logs := <-resultChan:
        return logs, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetFilterChanges(filterId *big.Int) ([]types.Log, error) {
    resultChan := make(chan []types.Log)
    errorChan := make(chan error)

    go func() {
        logs, err := r.Node.GetFilterChanges(filterId)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- logs
    }()
    select {
    case logs := <-resultChan:
        return logs, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) UninstallFilter(filterId *big.Int) (bool, error) {
    resultChan := make(chan bool)
    errorChan := make(chan error)

    go func() {
        boolean, err := r.Node.UninstallFilter(filterId)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- boolean
    }()
    select {
    case boolean := <-resultChan:
        return boolean, nil
    case err := <-errorChan:
        return false, err
    }
}
func (r *RpcInner) GetNewFilter(filter ethereum.FilterQuery) (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := r.Node.GetNewFilter(&filter)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId
    }()
    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetNewBlockFilter() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := r.Node.GetNewBlockFilter()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId
    }()
    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetNewPendingTransactionFilter() (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)

    go func() {
        filterId, err := r.Node.GetNewPendingTransactionFilter()
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- filterId
    }()
    select {
    case filterId := <-resultChan:
        return filterId, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) GetStorageAt(address seleneCommon.Address, slot [32]byte, block seleneCommon.BlockTag) (*big.Int, error) {
    resultChan := make(chan *big.Int)
    errorChan := make(chan error)
    go func() {
        value, err := r.Node.GetStorageAt(address, slot, block)
        if err != nil {
            errorChan <- err
            return
        }
        resultChan <- value
    }()
    select {
    case value := <-resultChan:
        return value, nil
    case err := <-errorChan:
        return nil, err
    }
}
func (r *RpcInner) Version() (uint64, error) {
	return r.Node.ChainId(), nil
}

// Define a struct to simulate JSON-RPC request/response
type JsonRpcRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     int             `json:"id"`
}
type JsonRpcResponse struct {
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
	ID     int         `json:"id"`
}

// Server struct simulating server handle
type Server struct {
	Address string
	Methods map[string]http.HandlerFunc
	mu      sync.Mutex
}

// Start the server and listen for requests
func (r *RpcInner) StartServer() (*Server, string, error) {
	address := r.Address
	server := &Server{
		Address: address,
		Methods: map[string]http.HandlerFunc{},
	}
	// Use a listener to get the local address (port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, "", err
	}
	// Start the server asynchronously
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			rpcHandler(w, req)
		})
		if err := http.Serve(listener, nil); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	return server, listener.Addr().String(), nil
}

type RPCRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// JSON-RPC response structure
type RPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   string      `json:"error,omitempty"`
	ID      int         `json:"id"`
}

// Handle JSON-RPC requests
// Defines methods to call functions in the RPC Server
func rpcHandler(w http.ResponseWriter, r *http.Request) {
	var req RPCRequest
	var rpc RpcInner
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	// Handle the RPC methods
	switch req.Method {
	case "eth_getBalance":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			// address := req.Params[0].(seleneCommon.Address)
			addrStr := req.Params[0].(string)
			var addressStruct seleneCommon.Address
			// addrStr := address["Addr"].(string)
			addressCommon, err := utils.Hex_str_to_bytes(addrStr)
			if err != nil {
				errorChan <- err
				return
			}
			var b [20]byte
			copy(b[:], addressCommon)
			addressStruct.Addr = b
			
			// block := req.Params[1].(seleneCommon.BlockTag)

			blockMap := req.Params[1].(string)

			// Create an empty instance of BlockTag
			var blockTag seleneCommon.BlockTag
			switch blockMap {
			case "latest":
				blockTag.Latest = true
			case "finalized":
				blockTag.Finalized = true
			default:
				blockTag.Number, err = hexutil.DecodeUint64(blockMap)
				if err != nil {
					errorChan <- err
					return
				}
			}
			
			// fmt.Printf("Address: %v, blockTag: {\nnumber: %v\nlatest: %v\n finalized: %v\n}", addressStruct, blockTag.Number, blockTag.Latest, blockTag.Finalized)
			balance, err := rpc.GetBalance(addressStruct, blockTag)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- balance
		}()

		select {
		case balance := <-resultChan:
			writeRPCResponse(w, req.ID, balance.String(), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getTransactionCount":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			address := req.Params[0].(seleneCommon.Address)
			block := req.Params[1].(seleneCommon.BlockTag)
			nonce, err := rpc.GetTransactionCount(address, block)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- nonce
		}()

		select {
		case nonce := <-resultChan:
			writeRPCResponse(w, req.ID, fmt.Sprintf("%d", nonce), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getBlockTransactionCountByHash":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			hash := req.Params[0].([32]byte)
			count, err := rpc.GetBlockTransactionCountByHash(hash)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- count
		}()

		select {
		case count := <-resultChan:
			writeRPCResponse(w, req.ID, fmt.Sprintf("%d", count), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getBlockTransactionCountByNumber":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			block := req.Params[0].(seleneCommon.BlockTag)
			nonce, err := rpc.GetBlockTransactionCountByNumber(block)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- nonce
		}()

		select {
		case nonce := <-resultChan:
			writeRPCResponse(w, req.ID, fmt.Sprintf("%d", nonce), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getCode":
		resultChan := make(chan []byte)
		errorChan := make(chan error)

		go func() {
			address := req.Params[0].(seleneCommon.Address)
			block := req.Params[1].(seleneCommon.BlockTag)
			code, err := rpc.GetCode(address, block)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- code
		}()

		select {
		case code := <-resultChan:
			writeRPCResponse(w, req.ID, string(code), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	// case "eth_call":
	// 	resultChan := make(chan []byte)
	// 	errorChan := make(chan error)

	// 	go func() {
	// 		tx := req.Params[0].(TransactionRequest)
	// 		block := req.Params[1].(seleneCommon.BlockTag)
	// 		result, err := rpc.Call(tx, block)
	// 		if err != nil {
	// 			errorChan <- err
	// 			return
	// 		}
	// 		resultChan <- result
	// 	}()

	// 	select {
	// 	case result := <-resultChan:
	// 		writeRPCResponse(w, req.ID, string(result), "")
	// 	case err := <-errorChan:
	// 		writeRPCResponse(w, req.ID, nil, err.Error())
	// 	}
	// case "eth_estimateGas":
	// 	resultChan := make(chan uint64)
	// 	errorChan := make(chan error)

	// 	go func() {
	// 		tx := req.Params[0].(TransactionRequest)
	// 		gas, err := rpc.EstimateGas(&tx)
	// 		if err != nil {
	// 			errorChan <- err
	// 			return
	// 		}
	// 		resultChan <- gas
	// 	}()

	// 	select {
	// 	case gas := <-resultChan:
	// 		writeRPCResponse(w, req.ID, fmt.Sprintf("%d", gas), "")
	// 	case err := <-errorChan:
	// 		writeRPCResponse(w, req.ID, nil, err.Error())
	// 	}
	case "eth_chainId":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			id, err := rpc.ChainId()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- id
		}()

		select {
		case id := <-resultChan:
			writeRPCResponse(w, req.ID, fmt.Sprintf("%d", id), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_gasPrice":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			result, err := rpc.GasPrice()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case result := <-resultChan:
			writeRPCResponse(w, req.ID, result.String(), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_maxPriorityFeePerGas":
		result := rpc.MaxPriorityFeePerGas()
		writeRPCResponse(w, req.ID, result.String(), "")
	case "eth_blockNumber":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			result, err := rpc.BlockNumber()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case result := <-resultChan:
			writeRPCResponse(w, req.ID, fmt.Sprintf("%d", result), "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getBlockByNumber": //
		resultChan := make(chan *seleneCommon.Block)
		errorChan := make(chan error)

		go func() {
			blockMap := req.Params[0].(string)

			// Create an empty instance of BlockTag
			var blockTag seleneCommon.BlockTag
			switch blockMap {
			case "latest":
				blockTag.Latest = true
			case "finalized":
				blockTag.Finalized = true
			default:
				blockTag.Number, err = hexutil.DecodeUint64(blockMap)
				if err != nil {
					errorChan <- err
					return
				}
			}

			fullTx := req.Params[1].(bool)
			result, err := rpc.GetBlockByNumber(blockTag, fullTx)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case result := <-resultChan:
			writeRPCResponse(w, req.ID, result, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getBlockByHash":
		resultChan := make(chan *seleneCommon.Block)
		errorChan := make(chan error)

		go func() {
			hash := req.Params[0].([32]byte)
			fullTx := req.Params[1].(bool)
			result, err := rpc.GetBlockByHash(hash, fullTx)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case result := <-resultChan:
			writeRPCResponse(w, req.ID, result, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_sendRawTransaction":
		resultChan := make(chan [32]byte)
		errorChan := make(chan error)

		go func() {
			rawTransaction := req.Params[0].([]uint8)
			hash, err := rpc.SendRawTransaction(rawTransaction)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- hash
		}()

		select {
		case hash := <-resultChan:
			writeRPCResponse(w, req.ID, hash, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getTransactionReceipt":
		resultChan := make(chan *types.Receipt)
		errorChan := make(chan error)

		go func() {
			hash := req.Params[0].([32]byte)
			receipt, err := rpc.GetTransactionReceipt(hash)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- receipt
		}()

		select {
		case receipt := <-resultChan:
			writeRPCResponse(w, req.ID, receipt, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getTransactionByHash":
		resultChan := make(chan *seleneCommon.Transaction)
		errorChan := make(chan error)

		go func() {
			hash := req.Params[0].([32]byte)
			transaction, err := rpc.GetTransactionByHash(hash)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- transaction
		}()

		select {
		case transaction := <-resultChan:
			writeRPCResponse(w, req.ID, transaction, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getTransactionByBlockHashAndIndex":
		resultChan := make(chan *seleneCommon.Transaction)
		errorChan := make(chan error)

		go func() {
			blockHash := req.Params[0].([32]byte)
			index := req.Params[1].(uint64)
			transaction, err := rpc.GetTransactionByBlockHashAndIndex(blockHash, index)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- transaction
		}()

		select {
		case transaction := <-resultChan:
			writeRPCResponse(w, req.ID, transaction, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getLogs":
		resultChan := make(chan []types.Log)
		errorChan := make(chan error)

		go func() {
			// filter := req.Params[0].(ethereum.FilterQuery)
			// First, assert params[0] as a map[string]interface{}
			filterMap := req.Params[0].(map[string]interface{})

			var filter ethereum.FilterQuery
		
			// Now, manually assign values from filterMap to filter struct
			if fromBlock, ok := filterMap["fromBlock"].(string); ok {
				filter.FromBlock = new(big.Int)
				filter.FromBlock.SetString(fromBlock, 0)
			}
			
			if toBlock, ok := filterMap["toBlock"].(string); ok {
				filter.ToBlock = new(big.Int)
				filter.ToBlock.SetString(toBlock, 0)
			}
		
			if addresses, ok := filterMap["addresses"].([]interface{}); ok {
				for _, addr := range addresses {
					if addrStr, ok := addr.(string); ok {
						filter.Addresses = append(filter.Addresses, common.HexToAddress(addrStr))
					}
				}
			}
			if blockHash, ok := filterMap["blockHash"].(string); ok {
				filter.BlockHash.SetBytes(common.Hex2Bytes(blockHash))
			} 
		
			if topics, ok := filterMap["topics"].([]interface{}); ok {
				for _, topic := range topics {
					if topicList, ok := topic.([]interface{}); ok {
						var topicGroup []common.Hash
						for _, t := range topicList {
							if topicStr, ok := t.(string); ok {
								topicGroup = append(topicGroup, common.HexToHash(topicStr))
							}
						}
						filter.Topics = append(filter.Topics, topicGroup)
					}
				}
			}
			logs, err := rpc.GetLogs(filter)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- logs
		}()

		select {
		case logs := <-resultChan:
			writeRPCResponse(w, req.ID, logs, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getFilterChanges":
		resultChan := make(chan []types.Log)
		errorChan := make(chan error)

		go func() {
			filterID := req.Params[0].(*big.Int)
			logs, err := rpc.GetFilterChanges(filterID)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- logs
		}()

		select {
		case logs := <-resultChan:
			writeRPCResponse(w, req.ID, logs, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_uninstallFilter":
		resultChan := make(chan bool)
		errorChan := make(chan error)

		go func() {
			filterID := req.Params[0].(*big.Int)
			result, err := rpc.UninstallFilter(filterID)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case result := <-resultChan:
			writeRPCResponse(w, req.ID, result, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_newFilter":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			filter := req.Params[0].(ethereum.FilterQuery)
			filterID, err := rpc.GetNewFilter(filter)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- filterID
		}()

		select {
		case filterID := <-resultChan:
			writeRPCResponse(w, req.ID, filterID, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_newBlockFilter":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			filterID, err := rpc.GetNewBlockFilter()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- filterID
		}()

		select {
		case filterID := <-resultChan:
			writeRPCResponse(w, req.ID, filterID, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_newPendingTransactionFilter":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			filterID, err := rpc.GetNewPendingTransactionFilter()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- filterID
		}()

		select {
		case filterID := <-resultChan:
			writeRPCResponse(w, req.ID, filterID, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_getStorageAt":
		resultChan := make(chan *big.Int)
		errorChan := make(chan error)

		go func() {
			address := req.Params[0].(seleneCommon.Address)
			slot := req.Params[1].([32]byte)
			blockTag := req.Params[2].(seleneCommon.BlockTag)
			storage, err := rpc.GetStorageAt(address, slot, blockTag)
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- storage
		}()

		select {
		case storage := <-resultChan:
			writeRPCResponse(w, req.ID, storage, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_coinbase":
		resultChan := make(chan [20]byte)
		errorChan := make(chan error)

		go func() {
			coinbaseAddress, err := rpc.Coinbase()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- coinbaseAddress
		}()

		select {
		case coinbaseAddress := <-resultChan:
			writeRPCResponse(w, req.ID, coinbaseAddress, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "eth_syncing":
		resultChan := make(chan SyncStatus)
		errorChan := make(chan error)

		go func() {
			syncStatus, err := rpc.Syncing()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- syncStatus
		}()

		select {
		case syncStatus := <-resultChan:
			writeRPCResponse(w, req.ID, syncStatus, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}
	case "net_version":
		resultChan := make(chan uint64)
		errorChan := make(chan error)

		go func() {
			result, err := rpc.Version()
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- result
		}()

		select {
		case version := <-resultChan:
			writeRPCResponse(w, req.ID, version, "")
		case err := <-errorChan:
			writeRPCResponse(w, req.ID, nil, err.Error())
		}

	default:
		writeRPCResponse(w, req.ID, nil, "Method not found")
	}
}

// Write a JSON-RPC response
func writeRPCResponse(w http.ResponseWriter, id int, result interface{}, err string) {
	resp := RPCResponse{
		Jsonrpc: "2.0",
		ID:      id,
		Result:  result,
		Error:   err,
	}
	json.NewEncoder(w).Encode(resp)
}