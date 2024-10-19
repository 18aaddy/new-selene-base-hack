package execution

import (
	"fmt"
	//"context"
	"encoding/hex"
	//"log"
	"math/big"
	Common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
//"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	//"github.com/ethereum/go-ethereum/ethdb"

	//"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
	//"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/triedb"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/BlocSoc-iitr/selene/common"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/crypto"

)
type B256 = Common.Hash
type U256 = big.Int
type HeaderReader interface {
	GetHeader(hash B256, number uint64) *types.Header
}
type Evm struct {
	execution *ExecutionClient
	chainID   uint64
	tag       common.BlockTag
}
func NewEvm(execution *ExecutionClient, chainID uint64, tag common.BlockTag) *Evm {
	return &Evm{
		execution: execution,
		chainID:   chainID,
		tag:       tag,
	}
}
func (e *Evm) CallInner(opts *CallOpts) (*core.ExecutionResult, error) {
	txContext := vm.TxContext{
		Origin:   *opts.From,
		GasPrice: opts.GasPrice,
	}
	tag:= e.tag
	block, err := e.execution.GetBlock(tag, false)
	if err != nil {
		return nil, err
	}
	blockContext := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash: func(n uint64) B256 {
			return B256{} // You might want to implement this properly
		},
		Coinbase:    block.Miner.Addr,
		BlockNumber: new(U256).SetUint64(block.Number),
		Time:        block.Timestamp,
		Difficulty:  block.Difficulty.ToBig(),
		GasLimit:    block.GasLimit,
		BaseFee:     block.BaseFeePerGas.ToBig(),
	}
	db:= rawdb.NewMemoryDatabase()
	tdb:= triedb.NewDatabase(db, nil)
	sdb:= state.NewDatabase(tdb, nil)
	//root:= trie.NewSecure(common.Hash{}, trie.NewDatabase(sdb))
	state, err := state.New(types.EmptyRootHash, sdb)
	//witness:=stateless.NewWitness(block,)
	//state.StartPrefetcher("hello",witness)
	// Create a new vm object
	var chainConfig *params.ChainConfig
	chainID:=e.chainID
	switch (int64(chainID)) {
		case MainnetID:
			chainConfig = params.MainnetChainConfig
		case HoleskyID:
			chainConfig = params.HoleskyChainConfig
		case SepoliaID:
			chainConfig = params.SepoliaChainConfig
		case LocalDevID:
			chainConfig = params.AllEthashProtocolChanges
		default:
			// Handle unknown chain ID
			chainConfig = nil
		}
		//Note other chainids not implemented(local testing)
		//	"github.com/ethereum/go-ethereum/params"

	config:= vm.Config{}
	nonceBytes, err := hex.DecodeString(block.Nonce)
	var nonce types.BlockNonce
	copy(nonce[:], nonceBytes)
	//Prefetch database: 
	var witness *stateless.Witness
	//need uncle hash for context so manually creatuing it
	header := &types.Header{
		ParentHash: 		  block.ParentHash,
		UncleHash: 			  block.Sha3Uncles,
		Coinbase: 			  block.Miner.Addr,
		Root: 				  block.StateRoot,
		TxHash: 			  block.TransactionsRoot,
		ReceiptHash: 		  block.ReceiptsRoot,
		Bloom: 				  types.Bloom(block.LogsBloom),
		Difficulty: 		  new(U256).SetUint64(block.Difficulty.Uint64()),
		Number: 			  new(U256).SetUint64(block.Number),
		GasLimit: 			  block.GasLimit,
		GasUsed: 			  block.GasUsed,
		Time: 				  block.Timestamp,
		Extra: 				  block.ExtraData,
		MixDigest: 			  block.MixHash,
		Nonce: 				  nonce,
		BaseFee: 			  new(U256).SetUint64(block.BaseFeePerGas.Uint64()),
		//WithdrawalsHash: 	  block.WithdrawalsRoot,
		BlobGasUsed: 		  block.BlobGasUsed,
		ExcessBlobGas: 		  block.ExcessBlobGas,
		//ParentBeaconBlockRoot: block.ParentBeaconBlockRoot,
		//RequestsHash: 		  block.RequestsRoot,
	}
	var(
	key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr   = crypto.PubkeyToAddress(key.PublicKey)
)
	genspec := &core.Genesis{
		Config:    params.AllCliqueProtocolChanges,
		Alloc: map[Common.Address]types.Account{
			addr: {Balance: big.NewInt(10000000000000000)},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}//using base fees as same as eip1559 blocks
	var engine = clique.New(params.AllCliqueProtocolChanges.Clique, db)
	//WithdrawalsHash,ParentBeaconBlockRoot,RequestsHash not found in block struct
	chain,_:=core.NewBlockChain(db, nil, genspec, nil,engine,config,nil)
	//don't know whether to use sdb or db
	//doubt in implementtation of genspec
	witness,err = stateless.NewWitness(header,chain)
	state.StartPrefetcher("evm", witness)
	evm := vm.NewEVM(blockContext,txContext,state,chainConfig,config)
// Prepare the call message
	msg := core.Message{
		From:              *opts.From,
		To:                opts.To,
		Value:             opts.Value,
		GasLimit:          opts.Gas.Uint64(),
		GasPrice:          opts.GasPrice,
		GasFeeCap:         nil, // Set if using EIP-1559
		GasTipCap:         nil, // Set if using EIP-1559
		Data:              opts.Data,
		AccessList:        nil, // Set if using EIP-2930
		SkipNonceChecks: false,
	}
	// Execute the call
	result, err := core.ApplyMessage(evm, &msg, new(core.GasPool).AddGas(opts.Gas.Uint64()))
	if err != nil {
		return nil, fmt.Errorf("failed to apply message: %w", err)
	}

	return result, nil
}
func (e *Evm) Call(opts *CallOpts) ([]byte, error) {
	result, err := e.CallInner(opts)
	if err != nil {
		return nil, fmt.Errorf("call failed: %w", err)
	}

	switch {
	case result.Failed():
		return nil, &EvmError{Kind: "execution reverted", Details: result.Revert()}
	default:
		return result.Return(), nil
	}
}
func (e *Evm) EstimateGas(opts *CallOpts) (uint64, error) {
	result, err := e.CallInner(opts)
	if err != nil {
		return 0, fmt.Errorf("gas estimation failed: %w", err)
	}

	return result.UsedGas, nil
}
