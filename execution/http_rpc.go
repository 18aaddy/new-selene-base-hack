package execution

// import (
// 	"strconv"

// 	seleneCommon "github.com/BlocSoc-iitr/selene/common"
// 	// "github.com/BlocSoc-iitr/selene/utils"
// 	"github.com/ethereum/go-ethereum"
// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/common/hexutil"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/rpc"
// 	"github.com/holiman/uint256"

// 	// "github.com/ethereum/go-ethereum/common"
// 	// "github.com/ethereum/go-ethereum/common/hexutil"
// 	// "github.com/ethereum/go-ethereum/rlp"
// 	// "github.com/holiman/uint256"
// 	// "bytes"
// 	// "encoding/json"
// 	// "fmt"
// 	"math/big"
// 	// "reflect"

// 	// "golang.org/x/crypto/sha3"
// )

// type HttpRpc struct {
// 	url      string
// 	provider *rpc.Client
// }

// func (h *HttpRpc) New(rpcUrl *string) (ExecutionRpc, error) {
// 	client, err := rpc.Dial(*rpcUrl)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &HttpRpc{
// 		url:      *rpcUrl,
// 		provider: client,
// 	}, nil
// }

// func (h *HttpRpc) GetProof(address *seleneCommon.Address, slots *[]common.Hash, block uint64) (EIP1186ProofResponse, error) {
// 	resultChan := make(chan struct {
// 		proof EIP1186ProofResponse
// 		err   error
// 	})

// 	go func() {
// 		var proof EIP1186ProofResponse
// 		err := h.provider.Call(&proof, "eth_getProof", address, slots, toBlockNumArg(block))
// 		resultChan <- struct {
// 			proof EIP1186ProofResponse
// 			err   error
// 		}{proof, err}
// 		close(resultChan)
// 	}()
// 	result := <-resultChan
// 	if result.err != nil {
// 		return EIP1186ProofResponse{}, result.err
// 	}
// 	return result.proof, nil
// }


// //TODO: CreateAccessList is throwing an error
// func (h *HttpRpc) CreateAccessList(opts CallOpts, block seleneCommon.BlockTag) (types.AccessList, error) {
// 	resultChan := make(chan struct {
// 		accessList types.AccessList
// 		err        error
// 	})

// 	go func() {
// 		var accessList types.AccessList
// 		err := h.provider.Call(&accessList, "eth_createAccessList", opts, block.String())
// 		resultChan <- struct {
// 			accessList types.AccessList
// 			err        error
// 		}{accessList, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return nil, result.err
// 	}
// 	return result.accessList, nil
// }

// func (h *HttpRpc) GetCode(address *seleneCommon.Address, block uint64) ([]byte, error) {
// 	resultChan := make(chan struct {
// 		code hexutil.Bytes
// 		err  error
// 	})

// 	go func() {
// 		var code hexutil.Bytes
// 		err := h.provider.Call(&code, "eth_getCode", address, toBlockNumArg(block))
// 		resultChan <- struct {
// 			code hexutil.Bytes
// 			err  error
// 		}{code, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return nil, result.err
// 	}
// 	return result.code, nil
// }

// func (h *HttpRpc) SendRawTransaction(data *[]byte) (common.Hash, error) {
// 	resultChan := make(chan struct {
// 		txHash common.Hash
// 		err    error
// 	})

// 	go func() {
// 		var txHash common.Hash
// 		err := h.provider.Call(&txHash, "eth_sendRawTransaction", hexutil.Bytes(*data))
// 		resultChan <- struct {
// 			txHash common.Hash
// 			err    error
// 		}{txHash, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return common.Hash{}, result.err
// 	}
// 	return result.txHash, nil
// }

// func (h *HttpRpc) GetTransactionReceipt(txHash *common.Hash) (types.Receipt, error) {
// 	resultChan := make(chan struct {
// 		receipt types.Receipt
// 		err     error
// 	})

// 	go func() {
// 		var receipt types.Receipt
// 		err := h.provider.Call(&receipt, "eth_getTransactionReceipt", txHash)
// 		resultChan <- struct {
// 			receipt types.Receipt
// 			err     error
// 		}{receipt, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return types.Receipt{}, result.err
// 	}
// 	return result.receipt, nil
// }

// func (h *HttpRpc) GetTransaction(txHash *common.Hash) (seleneCommon.Transaction, error) {
// 	resultChan := make(chan struct {
// 		tx  seleneCommon.Transaction
// 		err error
// 	})

// 	go func() {
// 		var tx seleneCommon.Transaction
// 		err := h.provider.Call(&tx, "eth_getTransactionByHash", txHash)
// 		resultChan <- struct {
// 			tx  seleneCommon.Transaction
// 			err error
// 		}{tx, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return seleneCommon.Transaction{}, result.err
// 	}
// 	return result.tx, nil
// }

// func (h *HttpRpc) GetLogs(filter *ethereum.FilterQuery) ([]types.Log, error) {
// 	resultChan := make(chan struct {
// 		logs []types.Log
// 		err  error
// 	})

// 	go func() {
// 		var logs []types.Log
// 		err := h.provider.Call(&logs, "eth_getLogs", toFilterArg(*filter))
// 		resultChan <- struct {
// 			logs []types.Log
// 			err  error
// 		}{logs, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return nil, result.err
// 	}
// 	return result.logs, nil
// }

// func (h *HttpRpc) GetFilterChanges(filterID *uint256.Int) ([]types.Log, error) {
// 	resultChan := make(chan struct {
// 		logs []types.Log
// 		err  error
// 	})

// 	go func() {
// 		var logs []types.Log
// 		err := h.provider.Call(&logs, "eth_getFilterChanges", filterID.Hex())
// 		resultChan <- struct {
// 			logs []types.Log
// 			err  error
// 		}{logs, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return nil, result.err
// 	}
// 	return result.logs, nil
// }

// func (h *HttpRpc) UninstallFilter(filterID *uint256.Int) (bool, error) {
// 	resultChan := make(chan struct {
// 		result bool
// 		err    error
// 	})

// 	go func() {
// 		var result bool
// 		err := h.provider.Call(&result, "eth_uninstallFilter", filterID.Hex())
// 		resultChan <- struct {
// 			result bool
// 			err    error
// 		}{result, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return false, result.err
// 	}
// 	return result.result, nil
// }

// func (h *HttpRpc) GetNewFilter(filter *ethereum.FilterQuery) (uint256.Int, error) {
// 	resultChan := make(chan struct {
// 		filterID uint256.Int
// 		err      error
// 	})

// 	go func() {
// 		var filterID hexutil.Big
// 		err := h.provider.Call(&filterID, "eth_newFilter", toFilterArg(*filter))
// 		filterResult := big.Int(filterID)
// 		resultChan <- struct {
// 			filterID uint256.Int
// 			err      error
// 		}{*uint256.MustFromBig(&filterResult), err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return uint256.Int{}, result.err
// 	}
// 	return result.filterID, nil
// }

// func (h *HttpRpc) GetNewBlockFilter() (uint256.Int, error) {
// 	resultChan := make(chan struct {
// 		filterID uint256.Int
// 		err      error
// 	})

// 	go func() {
// 		var filterID hexutil.Big
// 		err := h.provider.Call(&filterID, "eth_newBlockFilter")
// 		filterResult := big.Int(filterID)
// 		resultChan <- struct {
// 			filterID uint256.Int
// 			err      error
// 		}{*uint256.MustFromBig(&filterResult), err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return uint256.Int{}, result.err
// 	}
// 	return result.filterID, nil
// }

// func (h *HttpRpc) GetNewPendingTransactionFilter() (uint256.Int, error) {
// 	resultChan := make(chan struct {
// 		filterID uint256.Int
// 		err      error
// 	})

// 	go func() {
// 		var filterID hexutil.Big
// 		err := h.provider.Call(&filterID, "eth_newPendingTransactionFilter")
// 		filterResult := big.Int(filterID)
// 		resultChan <- struct {
// 			filterID uint256.Int
// 			err      error
// 		}{*uint256.MustFromBig(&filterResult), err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return uint256.Int{}, result.err
// 	}
// 	return result.filterID, nil
// }

// func (h *HttpRpc) ChainId() (uint64, error) {
// 	resultChan := make(chan struct {
// 		chainID uint64
// 		err     error
// 	})

// 	go func() {
// 		var chainID hexutil.Uint64
// 		err := h.provider.Call(&chainID, "eth_chainId")
// 		resultChan <- struct {
// 			chainID uint64
// 			err     error
// 		}{uint64(chainID), err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return 0, result.err
// 	}
// 	return result.chainID, nil
// }

// func (h *HttpRpc) GetFeeHistory(blockCount uint64, lastBlock uint64, rewardPercentiles *[]float64) (FeeHistory, error) {
// 	resultChan := make(chan struct {
// 		feeHistory FeeHistory
// 		err        error
// 	})

// 	go func() {
// 		var feeHistory FeeHistory
// 		err := h.provider.Call(&feeHistory, "eth_feeHistory", hexutil.Uint64(blockCount).String(), toBlockNumArg(lastBlock), rewardPercentiles)
// 		resultChan <- struct {
// 			feeHistory FeeHistory
// 			err        error
// 		}{feeHistory, err}
// 		close(resultChan)
// 	}()

// 	result := <-resultChan
// 	if result.err != nil {
// 		return FeeHistory{}, result.err
// 	}
// 	return result.feeHistory, nil
// }

// func toBlockNumArg(number uint64) string {
// 	if number == 0 {
// 		return "latest"
// 	}
// 	return "0x" + strconv.FormatUint(number, 16)
// }

// func toFilterArg(q ethereum.FilterQuery) map[string]interface{} {
// 	arg := make(map[string]interface{})
// 	if len(q.Addresses) > 0 {
// 		arg["address"] = q.Addresses
// 	}
// 	if len(q.Topics) > 0 {
// 		arg["topics"] = q.Topics
// 	}
// 	if q.FromBlock != nil {
// 		arg["fromBlock"] = q.FromBlock.String()
// 	}
// 	if q.ToBlock != nil {
// 		arg["toBlock"] = q.ToBlock.String()
// 	}
// 	return arg
// }

// type FeeHistory struct {
// 	BaseFeePerGas []hexutil.Big
// 	GasUsedRatio  []float64
// 	OldestBlock   *hexutil.Big
// 	Reward        [][]hexutil.Big
// }

// // defined storage proof	and EIP1186ProofResponse structs
// type StorageProof struct {
// 	Key   common.Hash     `json:"key"`
// 	Proof []hexutil.Bytes `json:"proof"`
// 	Value *uint256.Int    `json:"value"`
// }
// type EIP1186ProofResponse struct {
// 	Address      common.Address  `json:"address"`
// 	Balance      *uint256.Int    `json:"balance"`
// 	CodeHash     common.Hash     `json:"codeHash"`
// 	Nonce        hexutil.Uint64  `json:"nonce"`
// 	StorageHash  common.Hash     `json:"storageHash"`
// 	AccountProof []hexutil.Bytes `json:"accountProof"`
// 	StorageProof []StorageProof  `json:"storageProof"`
// }
// type Account struct {
// 	Balance     *big.Int
// 	Nonce       uint64
// 	CodeHash    common.Hash
// 	Code        []byte
// 	StorageHash common.Hash
// 	Slots       map[common.Hash]*big.Int
// }
// type CallOpts struct {
// 	From     *common.Address `json:"from,omitempty"`
// 	To       *common.Address `json:"to,omitempty"`
// 	Gas      *big.Int        `json:"gas,omitempty"`
// 	GasPrice *big.Int        `json:"gasPrice,omitempty"`
// 	Value    *big.Int        `json:"value,omitempty"`
// 	Data     []byte          `json:"data,omitempty"`
// }

// func (c *CallOpts) String() string {
// 	return fmt.Sprintf("CallOpts{From: %v, To: %v, Gas: %v, GasPrice: %v, Value: %v, Data: 0x%x}",
// 		c.From, c.To, c.Gas, c.GasPrice, c.Value, c.Data)
// }

// func (c *CallOpts) Serialize() ([]byte, error) {
// 	serialized := make(map[string]interface{})
// 	v := reflect.ValueOf(*c)
// 	t := v.Type()

// 	for i := 0; i < v.NumField(); i++ {
// 		field := v.Field(i)
// 		fieldName := t.Field(i).Name

// 		if !field.IsNil() {
// 			var value interface{}
// 			var err error

// 			switch field.Interface().(type) {
// 			case *common.Address:
// 				value = utils.Address_to_hex_string(*field.Interface().(*common.Address))
// 			case *big.Int:
// 				value = utils.U64_to_hex_string(field.Interface().(*big.Int).Uint64())
// 			case []byte:
// 				value, err = utils.Bytes_serialize(field.Interface().([]byte))
// 				if err != nil {
// 					return nil, fmt.Errorf("error serializing %s: %w", fieldName, err)
// 				}
// 			default:
// 				return nil, fmt.Errorf("unsupported type for field %s", fieldName)
// 			}

// 			serialized[fieldName] = value
// 		}
// 	}

// 	return json.Marshal(serialized)
// }

// func (c *CallOpts) Deserialize(data []byte) error {
// 	var serialized map[string]string
// 	if err := json.Unmarshal(data, &serialized); err != nil {
// 		return err
// 	}

// 	v := reflect.ValueOf(c).Elem()
// 	t := v.Type()

// 	for i := 0; i < v.NumField(); i++ {
// 		field := v.Field(i)
// 		fieldName := t.Field(i).Name

// 		if value, ok := serialized[fieldName]; ok {
// 			switch field.Interface().(type) {
// 			case *common.Address:
// 				addressBytes, err := utils.Hex_str_to_bytes(value)
// 				if err != nil {
// 					return fmt.Errorf("error deserializing %s: %w", fieldName, err)
// 				}
// 				addr := common.BytesToAddress(addressBytes)
// 				field.Set(reflect.ValueOf(&addr))
// 			case *big.Int:
// 				intBytes, err := utils.Hex_str_to_bytes(value)
// 				if err != nil {
// 					return fmt.Errorf("error deserializing %s: %w", fieldName, err)
// 				}
// 				bigInt := new(big.Int).SetBytes(intBytes)
// 				field.Set(reflect.ValueOf(bigInt))
// 			case []byte:
// 				byteValue, err := utils.Bytes_deserialize([]byte(value))
// 				if err != nil {
// 					return fmt.Errorf("error deserializing %s: %w", fieldName, err)
// 				}
// 				field.SetBytes(byteValue)
// 			default:
// 				return fmt.Errorf("unsupported type for field %s", fieldName)
// 			}
// 		}
// 	}

// 	return nil
// }

// func VerifyProof(proof [][]byte, root []byte, path []byte, value []byte) (bool, error) {
// 	expectedHash := root
// 	pathOffset := 0

// 	for i, node := range proof {
// 		if !bytes.Equal(expectedHash, keccak256(node)) {
// 			return false, nil
// 		}

// 		var nodeList [][]byte
// 		if err := rlp.DecodeBytes(node, &nodeList); err != nil {
// 			fmt.Println("Error decoding node:", err)
// 			return false, err
// 		}

// 		if len(nodeList) == 17 {
// 			if i == len(proof)-1 {
// 				// exclusion proof
// 				nibble := getNibble(path, pathOffset)
// 				if len(nodeList[nibble]) == 0 && isEmptyValue(value) {
// 					return true, nil
// 				}
// 			} else {
// 				nibble := getNibble(path, pathOffset)
// 				expectedHash = nodeList[nibble]
// 				pathOffset++
// 			}
// 		} else if len(nodeList) == 2 {
// 			if i == len(proof)-1 {
// 				// exclusion proof
// 				if !pathsMatch(nodeList[0], skipLength(nodeList[0]), path, pathOffset) && isEmptyValue(value) {
// 					return true, nil
// 				}

// 				// inclusion proof
// 				if bytes.Equal(nodeList[1], value) {
// 					return pathsMatch(nodeList[0], skipLength(nodeList[0]), path, pathOffset), nil
// 				}
// 			} else {
// 				nodePath := nodeList[0]
// 				prefixLength := sharedPrefixLength(path, pathOffset, nodePath)
// 				if prefixLength < len(nodePath)*2-skipLength(nodePath) {
// 					// Proof shows a divergent path , but we're not at the leaf yet
// 					return false, nil
// 				}
// 				pathOffset += prefixLength
// 				expectedHash = nodeList[1]
// 			}
// 		} else {
// 			return false, nil
// 		}
// 	}

// 	return false, nil
// }

// func pathsMatch(p1 []byte, s1 int, p2 []byte, s2 int) bool {
// 	len1 := len(p1)*2 - s1
// 	len2 := len(p2)*2 - s2

// 	if len1 != len2 {
// 		return false
// 	}

// 	for offset := 0; offset < len1; offset++ {
// 		n1 := getNibble(p1, s1+offset)
// 		n2 := getNibble(p2, s2+offset)
// 		if n1 != n2 {
// 			return false
// 		}
// 	}

// 	return true
// }

// // dead code
// func GetRestPath(p []byte, s int) string {
// 	var ret string
// 	for i := s; i < len(p)*2; i++ {
// 		n := getNibble(p, i)
// 		ret += fmt.Sprintf("%01x", n)
// 	}
// 	return ret
// }

// func isEmptyValue(value []byte) bool {
// 	emptyAccount := Account{
// 		Nonce:       0,
// 		Balance:     uint256.NewInt(0).ToBig(),
// 		StorageHash: [32]byte{0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21},
// 		CodeHash:    [32]byte{0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70},
// 	}

// 	encodedEmptyAccount, _ := rlp.EncodeToBytes(&emptyAccount)

// 	isEmptySlot := len(value) == 1 && value[0] == 0x80
// 	isEmptyAccount := bytes.Equal(value, encodedEmptyAccount)

// 	return isEmptySlot || isEmptyAccount
// }

// func sharedPrefixLength(path []byte, pathOffset int, nodePath []byte) int {
// 	skipLength := skipLength(nodePath)

// 	len1 := min(len(nodePath)*2-skipLength, len(path)*2-pathOffset)
// 	prefixLen := 0

// 	for i := 0; i < len1; i++ {
// 		pathNibble := getNibble(path, i+pathOffset)
// 		nodePathNibble := getNibble(nodePath, i+skipLength)
// 		if pathNibble != nodePathNibble {
// 			break
// 		}
// 		prefixLen++
// 	}

// 	return prefixLen
// }

// func skipLength(node []byte) int {
// 	if len(node) == 0 {
// 		return 0
// 	}

// 	nibble := getNibble(node, 0)
// 	switch nibble {
// 	case 0, 2:
// 		return 2
// 	case 1, 3:
// 		return 1
// 	default:
// 		return 0
// 	}
// }

// func getNibble(path []byte, offset int) byte {
// 	byteVal := path[offset/2]
// 	if offset%2 == 0 {
// 		return byteVal >> 4
// 	}
// 	return byteVal & 0xF
// }

// func keccak256(data []byte) []byte {
// 	hash := sha3.NewLegacyKeccak256()
// 	hash.Write(data)
// 	return hash.Sum(nil)
// }

// func EncodeAccount(proof *EIP1186ProofResponse) ([]byte, error) {
// 	account := Account{
// 		Nonce:       uint64(proof.Nonce),
// 		Balance:     proof.Balance.ToBig(),
// 		StorageHash: proof.StorageHash,
// 		CodeHash:    proof.CodeHash,
// 	}

// 	return rlp.EncodeToBytes(&account)
// }

// // Make a generic function for it
// func min(a, b int) int {
// 	if a < b {
// 		return a
// 	}
// 	return b
// }
