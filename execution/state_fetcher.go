package execution

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"time"

// 	// "github.com/ethereum/go-ethereum"
// 	"github.com/BlocSoc-iitr/selene/common"
// 	"github.com/ethereum/go-ethereum/rpc"
// )

// func FetchState() <-chan *common.Block{
//     // Connect to an Ethereum RPC node
//     client, err := rpc.Dial("https://eth-mainnet.g.alchemy.com/v2/j28GcevSYukh-GvSeBOYcwHOfIggF1Gt") // Replace with your node's RPC endpoint
//     if err != nil {
//         log.Fatalf("Failed to connect to the Ethereum node: %v", err)
//     }

//     // Create a ticker to fetch block headers every 10 seconds
//     ticker := time.NewTicker(10 * time.Second)
//     defer ticker.Stop()

//     for {
//         select {
//         case <-ticker.C:
//             // Fetch latest block header periodically
//             var header map[string]interface{} // Placeholder to hold the block header

//             err = client.CallContext(context.Background(), &header, "eth_getBlockByNumber", "latest", false)
//             if err != nil {
//                 log.Printf("Failed to fetch block header: %v", err)
//                 continue
//             }

//             // Process the block header
//             fmt.Printf("Fetched Block Header: %+v\n", header)
//         }
//     }
// }
