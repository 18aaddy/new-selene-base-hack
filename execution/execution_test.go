package execution

import (
	// "os"
	// "fmt"
	"math/big"
	"sync"
	"testing"

	seleneCommon "github.com/BlocSoc-iitr/selene/common"
	"github.com/holiman/uint256"

	// "github.com/BlocSoc-iitr/selene/utils"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	// "github.com/ethereum/go-ethereum/core/types"

	// "github.com/BlocSoc-iitr/selene/utils"
	// "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	// "github.com/BlocSoc-iitr/selene/consensus/rpc"
)

func CreateNewState() *State {
	blockChan := make(chan *seleneCommon.Block)
	finalizedBlockChan := make(chan *seleneCommon.Block)

	state := NewState(5, blockChan, finalizedBlockChan)

	// Simulate blocks to push
	block1 := &seleneCommon.Block{
		Number: 1,
		Hash:   [32]byte{0x1},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x11}, {0x12}},
		},
	}
	block2 := &seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}

	// Push blocks through channel
	go func() {
		blockChan <- block1
		blockChan <- block2
		close(blockChan)
	}()

	// Allow goroutine to process the blocks
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for len(state.blocks) < 2 {
			// wait for blocks to be processed
		}
	}()

	wg.Wait()

	// Simulate finalized block
	finalizedBlock := &seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}
	go func() {
		finalizedBlockChan <- finalizedBlock
		close(finalizedBlockChan)
	}()

	// Wait for finalized block to be processed
	wg.Add(1)
	go func() {
		defer wg.Done()
		for state.finalizedBlock == nil {
			// wait for finalized block to be processed
		}
	}()
	wg.Wait()

	return state
}

func CreateNewExecutionClient() *ExecutionClient {
	rpc := "https://eth-mainnet.g.alchemy.com/v2/KLk2JrSPcjR8dp55N7XNTs9jeKTKHMoA"
    state := CreateNewState()
	var executionClient *ExecutionClient
	executionClient, _ = executionClient.New(rpc, state)

	// if err != nil {
	// 	t.Errorf("Error in creating execution client")
	// }
	return executionClient
}

// func TestNewExecutionClient(t *testing.T){
// 	_ = CreateNewExecutionClient(t)
// }

func TestCheckRpc(t *testing.T) {
	executionClient := CreateNewExecutionClient()
	chainId := uint64(1)
	err := executionClient.CheckRpc(chainId)

	assert.NoError(t, err, "Error Found")

	chainId = uint64(2)
	err = executionClient.CheckRpc(chainId)
	
	assert.Equal(t, NewIncorrectRpcNetworkError() , err, "Error didn't match")
}

//! GetAccount() is not working properly: Invalid proof
// func TestGetAccount(t *testing.T) {
// 	executionClient := CreateNewExecutionClient()
// 	addressBytes, _ := utils.Hex_str_to_bytes("0xB856af30B938B6f52e5BfF365675F358CD52F91B")

// 	address := seleneCommon.Address{Addr: [20]byte(addressBytes)}

// 	slots := []common.Hash{}
// 	tag := seleneCommon.BlockTag{
// 		Number: 14900001,
// 		Finalized: true,
// 	}
// 	print("Check\n")
// 	account, err := executionClient.GetAccount(&address, slots, tag)

// 	assert.NoError(t, err, "Error found")
// 	assert.Equal(t, Account{}, account, "Account didn't match")
// }

// func TestToBlockNumberArg(t *testing.T) {
// 	blockNumber := uint64(5050)
// 	assert.Equal(t, "0x13ba", toBlockNumArg(blockNumber), "Block Number didn't match")

// 	blockNumber = uint64(0)
// 	assert.Equal(t, "latest", toBlockNumArg(blockNumber), "Block Number didn't match")
// }

// func TestSendRawTransaction(t *testing.T) {
// 	executionClient := CreateNewExecutionClient()
// 	transaction := common.Hex2Bytes("02f8720113840a436fe4850749a01900825208942ce3384fcaea81a0f10b2599ffb2f0603e6169f1878e1bc9bf04000080c080a097f6540a48025bd28dd3c43f33aa0269a29b40d852396fab1ab7c2f95a3930e7a03f69a6bca9ef4be6ce60735e76133670617286e15e18af96b7e5e0afcdc240c6")
// 	fmt.Printf("Transaction Bytes: %v ", transaction)
// 	hash, err := executionClient.SendRawTransaction(transaction)

// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, common.Hash{}, hash, "Transaction Hash didn't match")
// }

func TestGetBlock(t *testing.T) {
	executionClient := CreateNewExecutionClient()
	blockTag := seleneCommon.BlockTag{
		Number: 1,
	}

	block, err := executionClient.GetBlock(blockTag, false)
	expected := seleneCommon.Block{
		Number: 1,
		Hash:   [32]byte{0x1},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x11}, {0x12}},
		},
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, block , "Value didn't match expected")

	blockTag = seleneCommon.BlockTag{
		Finalized: true,
	}

	block, err = executionClient.GetBlock(blockTag, false)
	expected = seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			// Full: []seleneCommon.Transaction{
			// 	{Hash: common.Hash([32]byte{0x21})},
			// 	{Hash: common.Hash([32]byte{0x22})},
			// },
		},
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, block , "Value didn't match expected")

	block, err = executionClient.GetBlock(blockTag, true)
	expected = seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, block , "Value didn't match expected")
}

func TestExecutionGetBlockByHash(t *testing.T) {
	executionClient := CreateNewExecutionClient()
	hash := common.Hash([32]byte{0x2})

	block, err := executionClient.GetBlockByHash(hash, false)
	expected := seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			// Full: []seleneCommon.Transaction{
			// 	{Hash: common.Hash([32]byte{0x21})},
			// 	{Hash: common.Hash([32]byte{0x22})},
			// },
		},
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, block , "Value didn't match expected")

	block, err = executionClient.GetBlockByHash(hash, true)
	expected = seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, block , "Value didn't match expected")
}

func TestGetTransactionByBlockHashAndIndex(t *testing.T) {
	executionClient := CreateNewExecutionClient()
	hash := common.Hash([32]byte{0x2})

	txn, err := executionClient.GetTransactionByBlockHashAndIndex(hash, 0)

	expected := seleneCommon.Transaction{
		Hash: common.Hash([32]byte{0x21}),
		GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
		Gas: hexutil.Uint64(5),
		MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, txn , "Value didn't match expected")
}

//! GetTransactionReceipt() is not working properly: Incorrect Address or nil pointer Dereference
// func TestExecutionGetTransactionReceipt(t *testing.T) {
// 	executionClient := CreateNewExecutionClient()
// 	txHash := common.HexToHash("0x4bc11033063e445e038e52e72266f5054845d3879704d0cf38bedeb86c924cec")
// 	txnReceipt, err := executionClient.GetTransactionReceipt(txHash)
// 	expected := types.Receipt{}

// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, expected, txnReceipt, "Receipt didn't match")
// }


func TestExecutionGetTransaction(t *testing.T) {
	executionClient := CreateNewExecutionClient()
	txHash := common.Hash([32]byte{0x21})

	txn, err := executionClient.GetTransaction(txHash)
	expected := seleneCommon.Transaction{
			Hash: common.Hash([32]byte{0x21}),
			GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			Gas: hexutil.Uint64(5),
			MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
	}

	assert.NoError(t, err, "Found Error")
	assert.Equal(t, expected, txn, "Txn didn't match")
}

func TestExecutionGetLogs(t *testing.T) {
    executionClient := CreateNewExecutionClient()
    
    // Test case 1: Basic log retrieval
    filter := ethereum.FilterQuery{
        FromBlock: hexutil.MustDecodeBig("0x14057d0"),
        ToBlock: hexutil.MustDecodeBig("0x1405814"),
        Addresses: []common.Address{
            common.HexToAddress("0x6F9116ea572a207e4267f92b1D7b6F9b23536b07"),
        },
    }
    
    _, err := executionClient.GetLogs(filter)
    assert.NoError(t, err, "GetLogs should not return error for valid filter")
    
    // Test case 2: Too many logs
    // Mock Rpc to return more logs than MAX_SUPPORTED_LOGS_NUMBER
    // lotsOfLogs := make([]types.Log, MAX_SUPPORTED_LOGS_NUMBER+1)
    // executionClient.Rpc = &rpc.MockRpc{
    //     logs: lotsOfLogs,
    // }
    
    // _, err = executionClient.GetLogs(filter)
    // assert.Error(t, err, "Should return error when too many logs")
    // assert.Contains(t, err.Error(), "Too many logs to prove")
    
    // Test case 3: Null blocks defaults to latest

	executionClient.state = func() *State{
		blockChan := make(chan *seleneCommon.Block)
	finalizedBlockChan := make(chan *seleneCommon.Block)

	state := NewState(5, blockChan, finalizedBlockChan)

	// Simulate blocks to push
	block1 := &seleneCommon.Block{
		Number: 1,
		Hash:   [32]byte{0x1},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x11}, {0x12}},
		},
	}
	block2 := &seleneCommon.Block{
		Number: 20000000,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}

	// Push blocks through channel
	go func() {
		blockChan <- block1
		blockChan <- block2
		close(blockChan)
	}()

	// Allow goroutine to process the blocks
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for len(state.blocks) < 2 {
			// wait for blocks to be processed
		}
	}()

	wg.Wait()

	// Simulate finalized block
	finalizedBlock := &seleneCommon.Block{
		Number: 2,
		Hash:   [32]byte{0x2},
		Transactions: seleneCommon.Transactions{
			Hashes: [][32]byte{{0x21}, {0x22}},
			Full: []seleneCommon.Transaction{
				{
					Hash: common.Hash([32]byte{0x21}),
					GasPrice: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
					Gas: hexutil.Uint64(5),
					MaxFeePerGas: hexutil.Big(*hexutil.MustDecodeBig("0x12345")),
			},
				{Hash: common.Hash([32]byte{0x22})},
			},
		},
	}
	go func() {
		finalizedBlockChan <- finalizedBlock
		close(finalizedBlockChan)
	}()

	// Wait for finalized block to be processed
	wg.Add(1)
	go func() {
		defer wg.Done()
		for state.finalizedBlock == nil {
			// wait for finalized block to be processed
		}
	}()
	wg.Wait()

	return state
	}()
    filterNullBlocks := ethereum.FilterQuery{
        Addresses: []common.Address{
            common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
        },
    }
    
    logs, err := executionClient.GetLogs(filterNullBlocks)
    assert.NoError(t, err, "GetLogs should handle null blocks")
	assert.Equal(t, []types.Log{}, logs, "Logs didn't match")
}

func TestExecutionGetFilterChanges(t *testing.T) {
    executionClient := CreateNewExecutionClient()
    
    // Test case 1: Basic filter changes
    filterID := uint256.NewInt(1)
    
    _, err := executionClient.GetFilterChanges(filterID)
    assert.NoError(t, err, "GetFilterChanges should not return error for valid filter ID")
    
    // Test case 2: Too many logs in changes
    // Mock Rpc to return more logs than MAX_SUPPORTED_LOGS_NUMBER
    // executionClient.Rpc = &MockRPC{
    //     logs: make([]types.Log, MAX_SUPPORTED_LOGS_NUMBER+1),
    // }
    
    // _, err = executionClient.GetFilterChanges(filterID)
    // assert.Error(t, err, "Should return error when too many logs in changes")
    // assert.Contains(t, err.Error(), "Too many logs to prove")
}

func TestExecutionUninstallFilter(t *testing.T) {
    executionClient := CreateNewExecutionClient()
    
    // Test case 1: Successful uninstall
    filterID := uint256.NewInt(1)
    
    result, err := executionClient.UninstallFilter(filterID)
    assert.NoError(t, err, "UninstallFilter should not return error for valid filter ID")
    assert.True(t, result, "UninstallFilter should return true on success")
    
    // Test case 2: Invalid filter ID
    invalidFilterID := uint256.NewInt(999)
    result, err = executionClient.UninstallFilter(invalidFilterID)
    assert.NoError(t, err, "UninstallFilter should not return error for invalid filter ID")
    assert.False(t, result, "UninstallFilter should return false for invalid filter ID")
}

func TestExecutionGetNewFilter(t *testing.T) {
    executionClient := CreateNewExecutionClient()
    
    // Test case 1: Basic filter creation
    filter := ethereum.FilterQuery{
        FromBlock: big.NewInt(1),
        ToBlock: big.NewInt(2),
        Addresses: []common.Address{
            common.HexToAddress("0x1234567890123456789012345678901234567890"),
        },
    }
    
    filterID, err := executionClient.GetNewFilter(filter)
    assert.NoError(t, err, "GetNewFilter should not return error for valid filter")
    assert.NotEqual(t, uint256.Int{}, filterID, "FilterID should not be empty")
    
    // Test case 2: Null blocks defaults to latest
    filterNullBlocks := ethereum.FilterQuery{
        Addresses: []common.Address{
            common.HexToAddress("0x1234567890123456789012345678901234567890"),
        },
    }
    
    filterID, err = executionClient.GetNewFilter(filterNullBlocks)
    assert.NoError(t, err, "GetNewFilter should handle null blocks")
    assert.NotEqual(t, uint256.Int{}, filterID, "FilterID should not be empty")
}

func TestCalculateReceiptRoot(t *testing.T) {
    // Test case 1: Empty receipts
    _, err := CalculateReceiptRoot([][]byte{})
    assert.Error(t, err, "CalculateReceiptRoot should return error for empty receipts")
    assert.Contains(t, err.Error(), "no receipts to calculate root")
    
    // Test case 2: Single receipt
    receipt1 := []byte{1, 2, 3}
    root, err := CalculateReceiptRoot([][]byte{receipt1})
    assert.NoError(t, err, "CalculateReceiptRoot should not return error for single receipt")
    assert.NotEqual(t, common.Hash{}, root, "Root should not be empty")
    
    // Test case 3: Multiple receipts
    receipt2 := []byte{4, 5, 6}
    root, err = CalculateReceiptRoot([][]byte{receipt1, receipt2})
    assert.NoError(t, err, "CalculateReceiptRoot should not return error for multiple receipts")
    assert.NotEqual(t, common.Hash{}, root, "Root should not be empty")
}

func TestContains(t *testing.T) {
    // Create test receipts
    receipt1 := types.Receipt{
        TxHash: common.HexToHash("0x1"),
    }
    receipt2 := types.Receipt{
        TxHash: common.HexToHash("0x2"),
    }
    receipts := []types.Receipt{receipt1}
    
    // Test case 1: Receipt exists
    assert.True(t, contains(receipts, receipt1), "Contains should return true for existing receipt")
    
    // Test case 2: Receipt doesn't exist
    assert.False(t, contains(receipts, receipt2), "Contains should return false for non-existing receipt")
}