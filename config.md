# Configurations of our network

| node | ip              | p2p port    | rpc port        | tendermint node id |
|------|:----------------|:------------|:----------------|:-------------------|
|0     | 142.93.159.27   |             |                 |                    |
|1     | 142.93.172.101  |             |                 |                    |
|2     | 174.138.31.61   |             |                 |                    | 
|3     | 68.183.24.23    |             |                 |                    |


## commands to run on each machine
tendermint start --home ./mytestnet/node0 --proxy-app=kvstore --p2p.persistent-peers="ID1@142.93.159.27:26656,ID2@142.93.172.101:26656,ID3@174.138.31.61:26656,ID4@68.183.24.23:26656"
tendermint start --home ./mytestnet/node1 --proxy-app=kvstore --p2p.persistent-peers="ID1@142.93.159.27:26656,ID2@142.93.172.101:26656,ID3@174.138.31.61:26656,ID4@68.183.24.23:26656"
tendermint start --home ./mytestnet/node2 --proxy-app=kvstore --p2p.persistent-peers="ID1@142.93.159.27:26656,ID2@142.93.172.101:26656,ID3@174.138.31.61:26656,ID4@68.183.24.23:26656"
tendermint start --home ./mytestnet/node3 --proxy-app=kvstore --p2p.persistent-peers="ID1@142.93.159.27:26656,ID2@142.93.172.101:26656,ID3@174.138.31.61:26656,ID4@68.183.24.23:26656"
