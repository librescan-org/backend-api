# backend-api

This is the API backend module, serving a LibreScan blockchain database.  
The database access is read-only.

LibreScan works with any OpenEthereum derivative blockchain node, which exposes the trace_* RPC namespace in a compatible manner.
The node exposing the RPC endpoint must be running in full-archive mode.

Some example nodes are:

- [QuickNode](https://www.quicknode.com?tap_a=67226-09396e&tap_s=4155448-b52731&utm_source=affiliate&utm_campaign=generic&utm_content=affiliate_landing_page&utm_medium=generic)
- [LlamaNodes](https://llamarpc.com/eth)
- [Alchemy](https://alchemy.com)
- [Infura](https://infura.io)

Any client implementing OpenEthereum's RPC methods without modifications to its RPC response data format and logic is automatically compatible with LibreScan.

## Building

Only dockerized build is supported at this time, since GRPC protobuf artifacts are pulled from another image (see Dockerfile). You may manually copy them to your local machine, but this is not supported, please do not raise issues if you decide to go this path.

## Running

### Required environment variables

Postgres database connection details. All values are just examples to show the expected value formats:

```
POSTGRES_DB="postgres"  
POSTGRES_HOST="localhost"  
POSTGRES_PORT="5432"  
POSTGRES_USER="postgres"  
POSTGRES_PASSWORD="123"
```

### Optional environment variables (examples show the default values)

The service will listen on this address:port combo. Address can be omitted if localhost.

```
LISTEN=":9090"
```

The RPC client's access URL. Only provide when it is a QAN RPC and QAN specific features are needed on your service. Must be http or https. Websocket protocol (wss) is not supported at this time.

```
QAN_RPC_URL=""
```
