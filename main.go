package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/librescan-org/backend-api/api"

	storage "github.com/librescan-org/backend-db"
	"github.com/librescan-org/backend-db/database"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	env_LISTEN  = os.Getenv("LISTEN")
	env_RPC_URL = os.Getenv("QAN_RPC_URL")
)
var errDatabaseIsCorrupted = status.Errorf(codes.Internal, "database is corrupted")

func main() {
	grpcServer := grpc.NewServer()
	api.RegisterDataAPIServer(grpcServer, dataApi{StorageReader: database.LoadRepository()})
	var listen string
	if env_LISTEN == "" {
		listen = ":9090"
	} else {
		listen = env_LISTEN
	}
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("could not start the server: %v", err)
	}
}

// getTransactionMethod returns the transaction's method as a human-readable string.
func getTransactionMethod(transaction *storage.Transaction) (method string) {
	if len(transaction.Input) == 0 {
		method = "Transfer"
	} else {
		// TODO: External signature dictionary's value should be used for known signatures.
		// Even still, collisions happen all the time; it may be a good idea to return a list of possible method names.
		// However, if the called contract's ABI exists, the method name is obvious, assuming the ABI is
		// valid and not maliciously created for deliberate collision.
		method = "0x" + hex.EncodeToString(transaction.Input[:4])
	}
	return
}

// getQanAddressData returns the QAN specific address data if exists.
// If the current chain does not support this RPC call, both return values are nil.
func getQanAddressData(ctx context.Context, client *ethclient.Client, address *common.Address) (*api.QanAddressData, error) {
	if client == nil {
		return nil, nil
	}
	var response map[string]any
	if err := client.Client().CallContext(ctx, &response, "qan_xlinkGet", address.Hex(), true); err != nil {
		if _, isRpcErr := err.(rpc.Error); isRpcErr {
			err = nil
		}
		return nil, err
	}
	return &api.QanAddressData{
		Version:      uint32(response["Version"].(float64)),
		Created:      uint64(response["Created"].(float64)),
		ValidUntil:   uint64(response["ValidUntil"].(float64)),
		XlinkAddress: common.HexToHash(response["XlinkAddr"].(string)).Bytes(),
		Pem:          response["Pem"].(string),
	}, nil
}

// getQanContractData returns the QAN specific contract data for the address, if exists.
// If the current chain does not support this RPC call, both return values are nil.
func getQanContractData(ctx context.Context, client *ethclient.Client, address *common.Address) (*api.QanContractData, error) {
	if client == nil {
		return nil, nil
	}
	var response map[string]any
	if err := client.Client().CallContext(ctx, &response, "qan_qvmContractInfo", address.Hex()); err != nil {
		if _, isRpcErr := err.(rpc.Error); isRpcErr {
			err = nil
		}
		return nil, err
	}
	metadata := response["metadata"].(map[string]any)
	return &api.QanContractData{
		BinaryHash:        response["binaryHash"].(string),
		Source:            response["source"].(string),
		CompilerVersion:   metadata["COMPILER_VERSION"].(string),
		CompressorVersion: metadata["COMPRESSOR_VERSION"].(string),
		Language:          metadata["LANGUAGE"].(string),
	}, nil
}

type dataApi struct {
	api.UnimplementedDataAPIServer
	StorageReader storage.Reader
}

func (da dataApi) prepareApiBlock(block *storage.Block) (*api.Block, error) {
	var miner string
	if block.MinerAddressId != nil {
		minerAddress, err := da.StorageReader.GetAddressById(block.MinerAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		miner = minerAddress.Hex()
	}
	_, transactionIds, totalTxCount, err := da.StorageReader.ListTransactionsByBlockNumber(storage.BlockNumber(block.Number), nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	transactionFees := new(big.Int)
	for _, transactionId := range transactionIds {
		receipt, err := da.StorageReader.GetReceiptByTransactionId(transactionId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if receipt == nil {
			return nil, errDatabaseIsCorrupted
		}
		gasUsed := new(big.Int).SetUint64(receipt.GasUsed)
		transactionFees.Add(transactionFees, gasUsed.Mul(gasUsed, receipt.EffectiveGasPrice))
	}
	_, _, totalTraceCount, err := da.StorageReader.ListTracesByBlockNumber(block.Number, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	uncles, err := da.StorageReader.ListUnclesByBlockNumber(block.Number)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiUncles []*api.Uncle
	for _, uncle := range uncles {
		var uncleMiner string
		if block.MinerAddressId != nil {
			uncleMinerAddress, err := da.StorageReader.GetAddressById(uncle.MinerAddressId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			uncleMiner = uncleMinerAddress.Hex()
		}
		apiUncles = append(apiUncles, &api.Uncle{
			NephewNumber: uncle.BlockHeight,
			Number:       uncle.UncleHeight,
			Hash:         uncle.Hash.Hex(),
			ParentHash:   uncle.ParentHash.Hex(),
			Miner:        uncleMiner,
			Difficulty:   uncle.Difficulty.String(),
			GasLimit:     uncle.GasLimit,
			GasUsed:      uncle.GasUsed,
			Timestamp:    uncle.Timestamp,
			Reward:       uncle.Reward.String(),
		})
	}
	var parentHash string
	if block.Number == 0 {
		parentHash = common.Hash{}.Hex()
	} else {
		parentBlock, err := da.StorageReader.GetBlockByNumber(block.Number - 1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if parentBlock == nil {
			parentHash = common.Hash{}.Hex()
		} else {
			parentHash = parentBlock.Hash.Hex()
		}
	}
	var basePeePerGas, burntFees *string
	if block.BaseFeePerGas != nil {
		f := block.BaseFeePerGas.String()
		basePeePerGas = &f
	}
	if block.BaseFeePerGas != nil {
		f := new(big.Int).Mul(block.BaseFeePerGas, new(big.Int).SetUint64(block.GasUsed)).String()
		burntFees = &f
	}
	return &api.Block{
		Hash:             block.Hash.Hex(),
		Number:           block.Number,
		ParentHash:       parentHash,
		Nonce:            block.Nonce,
		Sha3Uncles:       block.Sha3Uncles.Hex(),
		LogsBloom:        block.LogsBloom.Bytes(),
		StateRoot:        block.StateRoot.Hex(),
		Miner:            miner,
		Difficulty:       block.Difficulty.String(),
		TotalDifficulty:  block.TotalDifficulty.String(),
		Size:             block.Size,
		ExtraData:        block.ExtraData,
		GasLimit:         block.GasLimit,
		GasUsed:          block.GasUsed,
		Timestamp:        block.Timestamp,
		TransactionCount: totalTxCount,
		TraceCount:       totalTraceCount,
		BaseFeePerGas:    basePeePerGas,
		BurntFees:        burntFees,
		TransactionFees:  transactionFees.String(),
		StaticReward:     block.StaticReward.String(),
		Uncles:           apiUncles,
		MixHash:          block.MixHash.Hex(),
	}, nil
}
func prepareApiTransactions(ctx context.Context, client *ethclient.Client, repo storage.Reader, transactions []*storage.Transaction, transactionIds []storage.TransactionId, block *storage.Block) ([]*api.Transaction, error) {
	var apiTransactions []*api.Transaction
	for i, tx := range transactions {
		fromAddress, err := repo.GetAddressById(tx.FromAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		var toAddress string
		var qanTransactionInput *api.QanTransactionInput
		if tx.ToAddressId != nil {
			to, err := repo.GetAddressById(*tx.ToAddressId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if to == nil {
				return nil, errDatabaseIsCorrupted
			}
			contractData, err := getQanContractData(ctx, client, to)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			var qanContractCallInput api.QanTransactionInput
			if contractData != nil {
				if err = json.Unmarshal(tx.Input, &qanContractCallInput); err != nil {
					return nil, status.Errorf(codes.Internal, err.Error())
				}
				qanTransactionInput = &qanContractCallInput
			}
			toAddress = to.Hex()
		}
		receipt, err := repo.GetReceiptByTransactionId(transactionIds[i])
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if receipt == nil {
			return nil, errDatabaseIsCorrupted
		}
		var receiptStatus api.TransactionReceiptStatus
		if receipt.Status {
			receiptStatus = api.Transaction_Success
		}
		var gasFeeCap, gasTipCap, baseFeePerGas *string
		if tx.GasFeeCap != nil {
			t := tx.GasFeeCap.String()
			gasFeeCap = &t
		}
		if tx.GasTipCap != nil {
			t := tx.GasTipCap.String()
			gasFeeCap = &t
		}

		if block.BaseFeePerGas != nil {
			t := block.BaseFeePerGas.String()
			baseFeePerGas = &t
		}
		var apiAccessObjects []*api.AccessObject
		addressToStorageKeys := make(map[common.Address][][]byte)
		storageKeys, err := repo.ListStorageKeysByTransactionId(transactionIds[i])
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		for _, storageKey := range storageKeys {
			address, err := repo.GetAddressById(storageKey.AddressId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if address == nil {
				return nil, errDatabaseIsCorrupted
			}
			addressToStorageKeys[*address] = append(addressToStorageKeys[*address], storageKey.StorageKey.Bytes())
		}
		for address, storageKeys := range addressToStorageKeys {
			apiAccessObjects = append(apiAccessObjects, &api.AccessObject{
				Address:     address.Hex(),
				StorageKeys: storageKeys,
			})
		}
		apiTransactions = append(apiTransactions, &api.Transaction{
			Hash:                     tx.Hash.Hex(),
			Method:                   getTransactionMethod(tx),
			Index:                    tx.Index,
			Nonce:                    strconv.Itoa(int(tx.Nonce)),
			BlockHash:                block.Hash.Hex(),
			BlockNumber:              block.Number,
			FromAddress:              fromAddress.Hex(),
			ToAddress:                toAddress,
			Value:                    tx.Value.String(),
			Gas:                      tx.Gas,
			GasUsed:                  receipt.GasUsed,
			GasPrice:                 tx.GasPrice.String(),
			Input:                    tx.Input,
			AccessObjects:            apiAccessObjects,
			BlockTimestamp:           block.Timestamp,
			MaxFeePerGas:             gasFeeCap,
			MaxPriorityFeePerGas:     gasTipCap,
			BaseFeePerGas:            baseFeePerGas,
			TransactionType:          uint32(tx.Type),
			TransactionFee:           receipt.TransactionFee().String(),
			ReceiptCumulativeGasUsed: receipt.CumulativeGasUsed,
			ReceiptStatus:            receiptStatus,
			QanTransactionInput:      qanTransactionInput,
		})
	}
	return apiTransactions, nil
}
func (da dataApi) ListBlocks(ctx context.Context, in *api.PaginationRequest) (*api.ListBlocksResponse, error) {
	blocks, totalBlockCount, err := da.StorageReader.ListBlocks(storage.NewOffsetPagination(uint8(in.Limit), in.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiBlocks []*api.Block
	for _, block := range blocks {
		apiBlock, err := da.prepareApiBlock(block)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if apiBlock == nil {
			continue
		}
		apiBlocks = append(apiBlocks, apiBlock)
	}
	return &api.ListBlocksResponse{
		Blocks:       apiBlocks,
		TotalRecords: totalBlockCount,
	}, nil
}
func (da dataApi) GetBlockByBlockNumber(ctx context.Context, in *api.GetBlockByBlockNumberRequest) (*api.BlockResponse, error) {
	block, err := da.StorageReader.GetBlockByNumber(uint64(in.Number))
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if block == nil {
		return nil, status.Errorf(codes.NotFound, "block not found")
	}
	apiBlock, err := da.prepareApiBlock(block)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if apiBlock == nil {
		return nil, status.Errorf(codes.NotFound, "block is not fully scraped")
	}
	latestBlockNumber, err := da.StorageReader.GetLatestBlockNumber()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &api.BlockResponse{
		Block:             apiBlock,
		LatestBlockNumber: latestBlockNumber,
	}, nil
}
func (da dataApi) GetBlockByBlockHash(ctx context.Context, in *api.GetBlockByBlockHashRequest) (*api.BlockResponse, error) {
	blockHash := common.HexToHash(in.Hash)
	block, err := da.StorageReader.GetBlockByHash(&blockHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if block == nil {
		return nil, status.Errorf(codes.NotFound, "block not found")
	}
	apiBlock, err := da.prepareApiBlock(block)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if apiBlock == nil {
		return nil, status.Errorf(codes.NotFound, "block is not fully scraped")
	}
	latestBlockNumber, err := da.StorageReader.GetLatestBlockNumber()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &api.BlockResponse{
		Block:             apiBlock,
		LatestBlockNumber: latestBlockNumber,
	}, nil
}
func (da dataApi) GetUncleByHash(ctx context.Context, in *api.GetBlockByBlockHashRequest) (*api.GetUncleByHashResponse, error) {
	uncleHash := common.HexToHash(in.Hash)
	uncle, err := da.StorageReader.GetUncleByUncleHash(&uncleHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if uncle == nil {
		return nil, status.Errorf(codes.NotFound, "uncle not found")
	}
	minerAddress, err := da.StorageReader.GetAddressById(uncle.MinerAddressId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if minerAddress == nil {
		return nil, errDatabaseIsCorrupted
	}
	return &api.GetUncleByHashResponse{
		Uncle: &api.Uncle{
			NephewNumber: uncle.BlockHeight,
			Hash:         uncle.Hash.Hex(),
			Number:       uncle.UncleHeight,
			ParentHash:   uncle.ParentHash.Hex(),
			Miner:        minerAddress.Hex(),
			Difficulty:   uncle.Difficulty.String(),
			GasLimit:     uncle.GasLimit,
			GasUsed:      uncle.GasUsed,
			Timestamp:    uncle.Timestamp,
			Reward:       uncle.Reward.String(),
		},
	}, nil
}
func (da dataApi) ListTransactions(ctx context.Context, in *api.PaginationRequest) (*api.TransactionsListResponse, error) {
	if in.Limit > math.MaxUint8 {
		return nil, status.Errorf(codes.InvalidArgument, "limit cannot be greater than 255")
	}
	var apiTransactions []*api.Transaction
	transactions, transactionIds, totalRecordsFound, err := da.StorageReader.ListTransactions(storage.NewOffsetPagination(uint8(in.Limit), in.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	blockNumberToBlock := make(map[storage.BlockNumber]*storage.Block)
	var client *ethclient.Client
	if env_RPC_URL != "" && len(transactions) != 0 {
		client, err = ethclient.DialContext(ctx, env_RPC_URL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
	}
	for i, tx := range transactions {
		if _, isBlockCached := blockNumberToBlock[tx.BlockNumber]; !isBlockCached {
			block, err := da.StorageReader.GetBlockByNumber(tx.BlockNumber)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if block == nil {
				return nil, errDatabaseIsCorrupted
			}
			blockNumberToBlock[tx.BlockNumber] = block
		}
		apiTransactionsChunk, err := prepareApiTransactions(ctx, client, da.StorageReader, []*storage.Transaction{tx}, []storage.TransactionId{transactionIds[i]}, blockNumberToBlock[tx.BlockNumber])
		if err != nil {
			return nil, err
		}
		apiTransactions = append(apiTransactions, apiTransactionsChunk[0])
	}
	return &api.TransactionsListResponse{
		Transactions: apiTransactions,
		TotalRecords: totalRecordsFound,
	}, nil
}
func (da dataApi) ListTransactionsByBlockNumber(ctx context.Context, in *api.ListTransactionsByBlockNumberRequest) (*api.TransactionsListResponse, error) {
	pagination := storage.NewOffsetPagination(uint8(in.Pagination.Limit), in.Pagination.Offset)
	transactions, transactionIds, totalRecordsFound, err := da.StorageReader.ListTransactionsByBlockNumber(in.BlockNumber, &pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	block, err := da.StorageReader.GetBlockByNumber(in.BlockNumber)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if block == nil {
		return nil, status.Errorf(codes.InvalidArgument, "block not found")
	}
	var client *ethclient.Client
	var apiTransactions []*api.Transaction
	if len(transactions) != 0 {
		if env_RPC_URL != "" {
			client, err = ethclient.DialContext(ctx, env_RPC_URL)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
		}
		apiTransactions, err = prepareApiTransactions(ctx, client, da.StorageReader, transactions, transactionIds, block)
	}
	return &api.TransactionsListResponse{
		Transactions: apiTransactions,
		TotalRecords: totalRecordsFound}, err
}
func (da dataApi) ListTransactionsByAddress(ctx context.Context, in *api.ListTransactionsByAddressRequest) (*api.TransactionsListResponse, error) {
	transactions, transactionIds, totalRecordsFound, err := da.StorageReader.ListTransactionsByAddress(common.HexToAddress(in.Address), storage.OffsetPagination{
		Limit:  uint8(in.Pagination.Limit),
		Offset: in.Pagination.Offset,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiTransactions []*api.Transaction
	blockNumberToBlock := make(map[storage.BlockNumber]*storage.Block)
	var client *ethclient.Client
	if env_RPC_URL != "" && len(transactions) != 0 {
		client, err = ethclient.DialContext(ctx, env_RPC_URL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
	}
	for i, tx := range transactions {
		if _, isBlockCached := blockNumberToBlock[tx.BlockNumber]; !isBlockCached {
			block, err := da.StorageReader.GetBlockByNumber(tx.BlockNumber)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if block == nil {
				return nil, errDatabaseIsCorrupted
			}
			blockNumberToBlock[tx.BlockNumber] = block
		}
		apiTransactionsChunk, err := prepareApiTransactions(ctx, client, da.StorageReader, []*storage.Transaction{tx}, []storage.TransactionId{transactionIds[i]}, blockNumberToBlock[tx.BlockNumber])
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		apiTransactions = append(apiTransactions, apiTransactionsChunk[0])
	}
	return &api.TransactionsListResponse{
		Transactions: apiTransactions,
		TotalRecords: totalRecordsFound}, nil
}
func (da dataApi) GetTransactionByHash(ctx context.Context, in *api.GetTransactionRequest) (*api.GetTransactionResponse, error) {
	transactionHash := common.HexToHash(in.Hash)
	transaction, transactionId, err := da.StorageReader.GetTransactionByHash(&transactionHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if transaction == nil {
		return nil, status.Errorf(codes.NotFound, "transaction not found")
	}
	block, err := da.StorageReader.GetBlockByNumber(transaction.BlockNumber)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if block == nil {
		return nil, status.Errorf(codes.InvalidArgument, "block not found")
	}
	var client *ethclient.Client
	if env_RPC_URL != "" {
		client, err = ethclient.DialContext(ctx, env_RPC_URL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
	}
	apiTransactions, err := prepareApiTransactions(ctx, client, da.StorageReader, []*storage.Transaction{transaction}, []storage.TransactionId{transactionId}, block)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	logs, err := da.StorageReader.ListLogsByTransactionId(transactionId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiLogs []*api.Log
	for _, log := range logs {
		address, err := da.StorageReader.GetAddressById(log.AddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		eventType, err := da.StorageReader.GetEventTypeById(log.Topic0Id)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		var topic1, topic2, topic3 []byte
		if log.Topic1 != nil {
			topic1 = log.Topic1[:]
		}
		if log.Topic2 != nil {
			topic2 = log.Topic2[:]
		}
		if log.Topic3 != nil {
			topic3 = log.Topic3[:]
		}
		apiLogs = append(apiLogs, &api.Log{
			Index:          log.LogIndex,
			Address:        address.Hex(),
			EventSignature: eventType.Signature,
			Topic0:         eventType.Bytes(),
			Topic1:         topic1,
			Topic2:         topic2,
			Topic3:         topic3,
			Data:           log.Data,
		})
	}
	traces, blockNumber, timestamp, err := da.StorageReader.ListTracesByTransactionHash(&transactionHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	uniqueAddressHashes := make(map[storage.AddressId]common.Address)
	for _, trace := range traces {
		for _, addressId := range []storage.AddressId{trace.From, trace.To} {
			if _, cached := uniqueAddressHashes[addressId]; !cached {
				address, err := da.StorageReader.GetAddressById(addressId)
				if err != nil {
					return nil, status.Errorf(codes.Internal, err.Error())
				}
				if address == nil {
					return nil, status.Errorf(codes.InvalidArgument, "address not found")
				}
				uniqueAddressHashes[addressId] = *address
			}
		}
	}
	var apiTraces []*api.Trace
	for _, trace := range traces {
		apiTraces = append(apiTraces, &api.Trace{
			TransactionHash: transactionHash.Hex(),
			Index:           uint32(trace.Index),
			CallType:        trace.Type,
			Input:           trace.Input,
			FromAddress:     uniqueAddressHashes[trace.From].Hex(),
			ToAddress:       uniqueAddressHashes[trace.To].Hex(),
			Value:           trace.Value.String(),
			Gas:             trace.Gas,
			Error:           trace.Error,
			BlockNumber:     blockNumber,
			BlockTimestamp:  timestamp,
		})
	}
	stateChanges, err := da.StorageReader.ListStateChangesByTransactionHash(&transaction.Hash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiStateChanges []*api.StateChange
	for _, stateChange := range stateChanges {
		address, err := da.StorageReader.GetAddressById(stateChange.AddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		var apiStorageChanges []*api.StorageChange
		for _, storageChange := range stateChange.StorageChanges {
			apiStorageChanges = append(apiStorageChanges, &api.StorageChange{
				StorageAddress: storageChange.StorageAddress.Bytes(),
				ValueBefore:    storageChange.ValueBefore.Bytes(),
				ValueAfter:     storageChange.ValueAfter.Bytes(),
			})
		}
		apiStateChanges = append(apiStateChanges, &api.StateChange{
			Address:        address.Hex(),
			BalanceBefore:  stateChange.BalanceBefore.String(),
			BalanceAfter:   stateChange.BalanceAfter.String(),
			NonceBefore:    stateChange.NonceBefore,
			NonceAfter:     stateChange.NonceAfter,
			StorageChanges: apiStorageChanges,
		})
	}
	return &api.GetTransactionResponse{
		Transaction:  apiTransactions[0],
		Logs:         apiLogs,
		Traces:       apiTraces,
		StateChanges: apiStateChanges,
	}, nil
}
func (da dataApi) ListErc20TokenTransfers(ctx context.Context, in *api.ListErc20TokenTransfersRequest) (*api.ListErc20TokenTransfersResponse, error) {
	var tokenAddress, fromOrToFilterAddress *common.Address
	if in.TokenAddress != nil {
		a := common.HexToAddress(*in.TokenAddress)
		tokenAddress = &a
	}
	if in.FromOrToAddress != nil {
		a := common.HexToAddress(*in.FromOrToAddress)
		fromOrToFilterAddress = &a
	}
	paginaton := storage.NewOffsetPagination(uint8(in.Pagination.Limit), in.Pagination.Offset)
	erc20TokenTransfers, totalTransfers, err := da.StorageReader.ListErc20TokenTransfers(tokenAddress, fromOrToFilterAddress, &paginaton)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	addressCache := make(map[storage.AddressId]common.Address)
	txCache := make(map[storage.TransactionId]storage.Transaction)
	getTransactionById := func(id storage.TransactionId) (*storage.Transaction, error) {
		if _, cached := txCache[id]; !cached {
			tx, err := da.StorageReader.GetTransactionById(id)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if tx == nil {
				return nil, errDatabaseIsCorrupted
			}
			txCache[id] = *tx
		}
		tx := txCache[id]
		return &tx, nil
	}
	getAddressById := func(id storage.AddressId) (string, error) {
		if _, cached := addressCache[id]; !cached {
			address, err := da.StorageReader.GetAddressById(id)
			if err != nil {
				return "", status.Errorf(codes.Internal, err.Error())
			}
			if address == nil {
				return "", errDatabaseIsCorrupted
			}
			addressCache[id] = *address
		}
		return addressCache[id].Hex(), nil
	}
	erc20TokenCache := make(map[storage.AddressId]*storage.Erc20Token)
	for _, transfer := range erc20TokenTransfers {
		if _, cached := erc20TokenCache[transfer.TokenAddressId]; cached {
			continue
		}
		erc20Token, err := da.StorageReader.GetErc20TokenByAddressId(transfer.TokenAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if erc20Token == nil {
			return nil, errDatabaseIsCorrupted
		}
		erc20TokenCache[transfer.TokenAddressId] = erc20Token
	}

	transactionCache := make(map[storage.TransactionId]*storage.Transaction)
	blockCache := make(map[storage.BlockNumber]*storage.Block)
	erc20TokenTransferTimestampCache := make(map[storage.TransactionId]uint64)
	for _, transfer := range erc20TokenTransfers {
		transactionId := transfer.TransactionId
		if _, cached := transactionCache[transactionId]; !cached {
			transaction, err := da.StorageReader.GetTransactionById(transactionId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if transaction == nil {
				return nil, errDatabaseIsCorrupted
			}
			transactionCache[transactionId] = transaction
		}
		blockNumber := transactionCache[transactionId].BlockNumber
		if _, cached := blockCache[blockNumber]; !cached {
			block, err := da.StorageReader.GetBlockByNumber(blockNumber)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			if block == nil {
				return nil, errDatabaseIsCorrupted
			}
			blockCache[blockNumber] = block
		}
		erc20TokenTransferTimestampCache[transactionId] = blockCache[blockNumber].Timestamp
	}

	var apiErc20TokenTransfers []*api.Erc20TokenTransfer
	for _, transfer := range erc20TokenTransfers {
		transactionId := transfer.TransactionId
		tokenAddress, err := getAddressById(transfer.TokenAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		fromAddress, err := getAddressById(transfer.FromAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		toAddress, err := getAddressById(transfer.ToAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		transaction, err := getTransactionById(transactionId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if transaction == nil {
			return nil, errDatabaseIsCorrupted
		}
		erc20token := erc20TokenCache[transfer.TokenAddressId]
		apiErc20TokenTransfers = append(apiErc20TokenTransfers, &api.Erc20TokenTransfer{
			Method:          getTransactionMethod(transaction),
			BlockTimestamp:  erc20TokenTransferTimestampCache[transactionId],
			TokenName:       erc20token.Name,
			TokenSymbol:     erc20token.Symbol,
			TransactionHash: transaction.Hash.Hex(),
			LogIndex:        transfer.LogIndex,
			TokenAddress:    tokenAddress,
			FromAddress:     fromAddress,
			ToAddress:       toAddress,
			Value:           transfer.Value.String(),
		})
	}
	return &api.ListErc20TokenTransfersResponse{
		Erc20TokenTransfer: apiErc20TokenTransfers,
		TotalRecords:       totalTransfers,
	}, nil
}
func (da dataApi) GetSearchTermType(ctx context.Context, in *api.GetSearchTermTypeRequest) (*api.GetSearchTermTypeResponse, error) {
	normalizedSearchTerm := strings.ToLower(in.SearchTerm)
	var hadPrefix bool
	if strings.HasPrefix(normalizedSearchTerm, "0x") {
		normalizedSearchTerm = normalizedSearchTerm[2:]
		hadPrefix = true
	}
	isValidHex, _ := regexp.MatchString("^[0-9a-f]+$", normalizedSearchTerm)
	if !isValidHex {
		return nil, status.Errorf(codes.NotFound, "invalid characters in search term")
	}
	if len(normalizedSearchTerm) == 40 {
		return &api.GetSearchTermTypeResponse{
			Type: api.GetSearchTermTypeResponse_Address,
		}, nil
	} else if len(normalizedSearchTerm) == 64 {
		potentialBlockOrTxHash := common.HexToHash(normalizedSearchTerm)
		block, err := da.StorageReader.GetBlockByHash(&potentialBlockOrTxHash)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if block != nil {
			return &api.GetSearchTermTypeResponse{
				Type: api.GetSearchTermTypeResponse_BlockHash,
			}, nil
		}
		transaction, _, err := da.StorageReader.GetTransactionByHash(&potentialBlockOrTxHash)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if transaction != nil {
			return &api.GetSearchTermTypeResponse{
				Type: api.GetSearchTermTypeResponse_Transaction,
			}, nil
		}
	} else if hadPrefix {
		return nil, status.Errorf(codes.NotFound, "invalid hash length")
	} else if potentialBlockNumber, err := strconv.ParseUint(normalizedSearchTerm, 10, 64); err == nil {
		block, err := da.StorageReader.GetBlockByNumber(potentialBlockNumber)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if block != nil {
			return &api.GetSearchTermTypeResponse{
				Type: api.GetSearchTermTypeResponse_BlockNumber,
			}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "nothing was found")
}
func (da dataApi) ListTracesByBlockNumber(ctx context.Context, in *api.ListTracesByBlockNumberRequest) (*api.ListTracesResponse, error) {
	pagination := storage.NewOffsetPagination(uint8(in.Pagination.Limit), in.Pagination.Offset)
	traces, timestamp, totalRecordsFound, err := da.StorageReader.ListTracesByBlockNumber(in.BlockNumber, &pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiTraces []*api.Trace
	for _, trace := range traces {
		tx, err := da.StorageReader.GetTransactionById(trace.TransactionId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		fromAddress, err := da.StorageReader.GetAddressById(trace.From)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if fromAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		toAddress, err := da.StorageReader.GetAddressById(trace.To)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if toAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		apiTraces = append(apiTraces, &api.Trace{
			TransactionHash: tx.Hash.Hex(),
			Index:           uint32(trace.Index),
			CallType:        trace.Type,
			Input:           trace.Input,
			FromAddress:     fromAddress.Hex(),
			ToAddress:       toAddress.Hex(),
			Value:           trace.Value.String(),
			Gas:             trace.Gas,
			Error:           trace.Error,
			BlockNumber:     in.BlockNumber,
			BlockTimestamp:  timestamp,
		})
	}
	return &api.ListTracesResponse{
		Traces:       apiTraces,
		TotalRecords: totalRecordsFound,
	}, nil
}
func (da dataApi) ListTraces(ctx context.Context, in *api.PaginationRequest) (*api.ListTracesResponse, error) {
	pagination := storage.NewOffsetPagination(uint8(in.Limit), in.Offset)
	traces, blockNumbers, timestamps, totalRecordsFound, err := da.StorageReader.ListTraces(&pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var apiTraces []*api.Trace
	for i, trace := range traces {
		tx, err := da.StorageReader.GetTransactionById(trace.TransactionId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		fromAddress, err := da.StorageReader.GetAddressById(trace.From)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if fromAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		toAddress, err := da.StorageReader.GetAddressById(trace.To)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if toAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		apiTraces = append(apiTraces, &api.Trace{
			TransactionHash: tx.Hash.Hex(),
			Index:           uint32(trace.Index),
			CallType:        trace.Type,
			Input:           trace.Input,
			FromAddress:     fromAddress.Hex(),
			ToAddress:       toAddress.Hex(),
			Value:           trace.Value.String(),
			Gas:             trace.Gas,
			Error:           trace.Error,
			BlockNumber:     blockNumbers[i],
			BlockTimestamp:  timestamps[i],
		})
	}
	return &api.ListTracesResponse{
		Traces:       apiTraces,
		TotalRecords: totalRecordsFound,
	}, nil
}
func (da dataApi) InspectAddress(ctx context.Context, in *api.InspectAddressRequest) (*api.InspectAddressResponse, error) {
	resp, err := da.GetSearchTermType(context.TODO(), &api.GetSearchTermTypeRequest{SearchTerm: in.Address})
	if err != nil {
		return nil, err
	}
	if resp.Type != api.GetSearchTermTypeResponse_Address {
		return nil, status.Errorf(codes.NotFound, "not an address")
	}
	address := common.HexToAddress(in.Address)
	addressId, err := da.StorageReader.GetAddressIdByHash(address)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	latestBlockNumber, err := da.StorageReader.GetLatestBlockNumber()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	if latestBlockNumber == nil {
		return nil, status.Errorf(codes.NotFound, "no blocks in database")
	}
	block, err := da.StorageReader.GetBlockByNumber(*latestBlockNumber)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	weiBalance, err := da.StorageReader.GetWeiBalanceAtBlock(addressId, block.Number)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	firstTxSent, err := da.StorageReader.GetFirstTxSent(addressId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var firstTxSentStr *string
	if firstTxSent != nil {
		t := firstTxSent.Hex()
		firstTxSentStr = &t
	}
	lastTxSent, err := da.StorageReader.GetLastTxSent(addressId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var lastTxSentStr *string
	if lastTxSent != nil {
		t := lastTxSent.Hex()
		lastTxSentStr = &t
	}
	tokenHoldings, err := da.StorageReader.ListErc20TokenBalancesAtBlock(addressId, block.Number)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	tokenCache := make(map[storage.AddressId]*storage.Erc20Token)
	for _, holding := range tokenHoldings {
		if tokenCache[holding.TokenAddressId] == nil {
			token, err := da.StorageReader.GetErc20TokenByAddressId(holding.TokenAddressId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
			}
			tokenCache[holding.TokenAddressId] = token
		}
	}
	var apiTokenHoldings []*api.TokenHolding
	for _, holding := range tokenHoldings {
		tokenAddress, err := da.StorageReader.GetAddressById(holding.TokenAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		token := tokenCache[holding.TokenAddressId]
		apiTokenHoldings = append(apiTokenHoldings, &api.TokenHolding{
			TokenAddress: tokenAddress.Hex(),
			Decimals:     uint32(token.Decimals),
			Name:         token.Name,
			Symbol:       token.Symbol,
			Value:        holding.Balance.String(),
		})
	}
	contract, err := da.StorageReader.GetContractByAddressId(addressId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var client *ethclient.Client
	if env_RPC_URL != "" {
		client, err = ethclient.DialContext(ctx, env_RPC_URL)
		if err != nil {
			return nil, err
		}
	}
	qanAddressData, err := getQanAddressData(ctx, client, &address)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var contractData *api.ContractData
	if contract != nil {
		qanContractData, err := getQanContractData(ctx, client, &address)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		contractTransaction, err := da.StorageReader.GetTransactionById(contract.TransactionId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if contractTransaction == nil {
			return nil, errDatabaseIsCorrupted
		}
		creatorAddress, err := da.StorageReader.GetAddressById(contractTransaction.FromAddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if creatorAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		bytecode, err := da.StorageReader.GetByteCode(contract.BytecodeId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if bytecode == nil {
			return nil, errDatabaseIsCorrupted
		}
		contractData = &api.ContractData{
			CreatorAddress:     creatorAddress.Hex(),
			CreatorTransaction: contractTransaction.Hash.Hex(),
			Bytecode:           *bytecode,
			QanContractData:    qanContractData,
		}
	}
	token, err := da.StorageReader.GetErc20TokenByAddressId(addressId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	var tokenStatistics *api.TokenStatistics
	if token != nil {
		tokenAddress, err := da.StorageReader.GetAddressById(addressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		if tokenAddress == nil {
			return nil, errDatabaseIsCorrupted
		}
		_, totalTransfers, err := da.StorageReader.ListErc20TokenTransfers(tokenAddress, nil, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		holders, err := da.StorageReader.GetErc20TokenHolders(token.AddressId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		tokenStatistics = &api.TokenStatistics{
			TokenAddress:   tokenAddress.Hex(),
			Decimals:       uint32(token.Decimals),
			Name:           token.Name,
			Symbol:         token.Symbol,
			MaxTotalSupply: token.TotalSupply.String(),
			Holders:        holders,
			TotalTransfers: totalTransfers,
		}
	}
	apiWalletStatistics := api.WalletStatistics{
		WeiBalance:    weiBalance.String(),
		TokenHoldings: apiTokenHoldings,
		FirstTxSent:   firstTxSentStr,
		LastTxSent:    lastTxSentStr,
	}
	apiWalletStatistics.QanAddressData = qanAddressData
	return &api.InspectAddressResponse{
		WalletStatistics: &apiWalletStatistics,
		ContractData:     contractData,
		TokenStatistics:  tokenStatistics,
	}, nil
}
