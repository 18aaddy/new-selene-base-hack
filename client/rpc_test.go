package client

import (
	// "testing"

	// "bytes"
	"encoding/json"
	// "fmt"
	// "io/ioutil"
	// "net/http"

	// seleneCommon "github.com/BlocSoc-iitr/selene/common"
	// "github.com/ethereum/go-ethereum"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/stretchr/testify/assert"
)

// func TestStartRpc(t *testing.T) {
// 	rpc := Rpc{}.New(&Node{}, nil, 0)
// 	address, err := rpc.Start()
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, "127.0.0.1:8545", address, "Address didn't match expected")

// 	addressRpc := "127.0.0.1"
// 	rpc = Rpc{}.New(&Node{}, &addressRpc, 8080)
// 	address, err = rpc.Start()
// 	assert.NoError(t, err, "Found Error")
// 	assert.Equal(t, "127.0.0.1:8080", address, "Address didn't match expected")
// }

type RpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      int           `json:"id"`
}

type RpcResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Result  json.RawMessage `json:"result"` // Block data comes here
	Error   *RpcError       `json:"error,omitempty"`
}

type RpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// func TestSendGetBlockRequest(t *testing.T) {
// 	rpc := Rpc{}.New(&Node{}, nil, 0)
// 	address, err := rpc.Start()
// 	assert.NoError(t, err, "Found Error")

// 	// Create the RPC request payload
// 	blockNumber := seleneCommon.BlockTag{
// 		Latest: true,
// 		Finalized: false,
// 		Number: 0,
// 		} // You can use a hex value (e.g., "0x1B4") for a specific block number
// 	rpcReq := RpcRequest{
// 		Jsonrpc: "2.0",
// 		Method:  "eth_getBlockByNumber",
// 		Params:  []interface{}{blockNumber, false}, // 'false' indicates we don't need full transaction objects
// 		Id:      1,
// 	}

// 	// Encode the request as JSON
// 	reqBody, err := json.Marshal(rpcReq)
// 	if err != nil {
// 		fmt.Println("Error marshaling request:", err)
// 	}

// 	// Send the request to an Ethereum node (replace the URL with your Ethereum node's endpoint)
// 	rpcURL := "http://" + address // Example: if you're running a local Ethereum node
// 	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(reqBody))
// 	if err != nil {
// 		fmt.Println("Error sending request:", err)
// 	}
// 	defer resp.Body.Close()

// 	// Read and parse the response
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading response:", err)
// 	}

// 	var rpcResp RpcResponse
// 	err = json.Unmarshal(respBody, &rpcResp)
// 	if err != nil {
// 		fmt.Println("Error unmarshaling response:", err)
// 	}

// 	if rpcResp.Error != nil {
// 		fmt.Printf("RPC Error: %s\n", rpcResp.Error.Message)
// 	}

// 	// Print the result (block data)
// 	fmt.Printf("Response body: %v", rpcResp)
// 	fmt.Printf("Block: %s\n", string(rpcResp.Result))
// 	assert.Equal(t, 0, 1, "Not Equal")
// }

// func TestSendGetLogsRequest(t *testing.T) {
// 	rpc := Rpc{}.New(&Node{}, nil, 0)
// 	address, err := rpc.Start()
// 	assert.NoError(t, err, "Found Error")

// 	// Create the RPC request payload
// 	filter := ethereum.FilterQuery{
// 		Addresses: []common.Address{common.HexToAddress("0xB856af30B938B6f52e5BfF365675F358CD52F91B")},
// 		Topics: [][]common.Hash{{common.HexToHash("0xb21924031f38635d45297d68e7b7a408d40b194d435b25eeccad41c522841bd5")}},
// 	} // You can use a hex value (e.g., "0x1B4") for a specific block number
// 	rpcReq := RpcRequest{
// 		Jsonrpc: "2.0",
// 		Method:  "eth_getLogs",
// 		Params:  []interface{}{filter}, // 'false' indicates we don't need full transaction objects
// 		Id:      1,
// 	}

// 	// Encode the request as JSON
// 	reqBody, err := json.Marshal(rpcReq)
// 	if err != nil {
// 		fmt.Println("Error marshaling request:", err)
// 	}

// 	// Send the request to an Ethereum node (replace the URL with your Ethereum node's endpoint)
// 	rpcURL := "http://" + address // Example: if you're running a local Ethereum node
// 	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(reqBody))
// 	if err != nil {
// 		fmt.Println("Error sending request:", err)
// 	}
// 	defer resp.Body.Close()

// 	// Read and parse the response
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading response:", err)
// 	}

// 	var rpcResp RpcResponse
// 	err = json.Unmarshal(respBody, &rpcResp)
// 	if err != nil {
// 		fmt.Println("Error unmarshaling response:", err)
// 	}

// 	if rpcResp.Error != nil {
// 		fmt.Printf("RPC Error: %s\n", rpcResp.Error.Message)
// 	}

// 	// Print the result (block data)
// 	fmt.Printf("Response body: %v", rpcResp)
// 	fmt.Printf("Logs: %s\n", string(rpcResp.Result))
// 	assert.Equal(t, 0, 1, "Not Equal")
// }

// func TestSendGetBlockRequest(t *testing.T) {
// 	rpc := Rpc{}.New(&Node{}, nil, 0)
// 	address, err := rpc.Start()
// 	assert.NoError(t, err, "Found Error")

// 	// Create the RPC request payload
// 	blockNumber := seleneCommon.BlockTag{
// 		Latest: true,
// 		Finalized: false,
// 		Number: 0,
// 		} // You can use a hex value (e.g., "0x1B4") for a specific block number
// 	rpcReq := RpcRequest{
// 		Jsonrpc: "2.0",
// 		Method:  "eth_getBalance",
// 		Params:  []interface{}{"0xB856af30B938B6f52e5BfF365675F358CD52F91B" ,blockNumber.String()}, // 'false' indicates we don't need full transaction objects
// 		Id:      1,
// 	}

// 	// Encode the request as JSON
// 	reqBody, err := json.Marshal(rpcReq)
// 	if err != nil {
// 		fmt.Println("Error marshaling request:", err)
// 	}

// 	// Send the request to an Ethereum node (replace the URL with your Ethereum node's endpoint)
// 	rpcURL := "http://" + address // Example: if you're running a local Ethereum node
// 	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(reqBody))
// 	if err != nil {
// 		fmt.Println("Error sending request:", err)
// 	}
// 	defer resp.Body.Close()

// 	// Read and parse the response
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println("Error reading response:", err)
// 	}

// 	var rpcResp RpcResponse
// 	err = json.Unmarshal(respBody, &rpcResp)
// 	if err != nil {
// 		fmt.Println("Error unmarshaling response:", err)
// 	}

// 	if rpcResp.Error != nil {
// 		fmt.Printf("RPC Error: %s\n", rpcResp.Error.Message)
// 	}

// 	// Print the result (block data)
// 	fmt.Printf("Response body: %v", rpcResp)
// 	fmt.Printf("Block: %s\n", string(rpcResp.Result))
// 	assert.Equal(t, 0, 1, "Not Equal")
// }