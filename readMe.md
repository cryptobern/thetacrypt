# Configurations of our network

| node | ip              | p2p port    | rpc port        | tendermint node id |
|------|:----------------|:------------|:----------------|:---------------------------------------|
|0     | 142.93.159.27   |             |                 |71abf2272bcac2f63a5461a85d3a59d4964f239f|
|1     | 142.93.172.101  |             |                 |733c2b6c5b090bd29223afff812cbed0a1fa49d7|
|2     | 174.138.31.61   |             |                 |ef3df96b7c929adca315a7781623205d9b0a5138| 
|3     | 68.183.24.23    |             |                 |d909a1b375ae730c332bae83a14c733ae0ffb028|


## commands to run on each machine
tendermint start --home ./mytestnet/node0 --proxy-app=kvstore --p2p.persistent-peers="71abf2272bcac2f63a5461a85d3a59d4964f239f@142.93.159.27:26656,733c2b6c5b090bd29223afff812cbed0a1fa49d7@142.93.172.101:26656,ef3df96b7c929adca315a7781623205d9b0a5138@174.138.31.61:26656,d909a1b375ae730c332bae83a14c733ae0ffb028@68.183.24.23:26656"

tendermint start --home ./mytestnet/node1 --proxy-app=kvstore --p2p.persistent-peers="71abf2272bcac2f63a5461a85d3a59d4964f239f@142.93.159.27:26656,733c2b6c5b090bd29223afff812cbed0a1fa49d7@142.93.172.101:26656,ef3df96b7c929adca315a7781623205d9b0a5138@174.138.31.61:26656,d909a1b375ae730c332bae83a14c733ae0ffb028@68.183.24.23:26656"

tendermint start --home ./mytestnet/node2 --proxy-app=kvstore --p2p.persistent-peers="71abf2272bcac2f63a5461a85d3a59d4964f239f@142.93.159.27:26656,733c2b6c5b090bd29223afff812cbed0a1fa49d7@142.93.172.101:26656,ef3df96b7c929adca315a7781623205d9b0a5138@174.138.31.61:26656,d909a1b375ae730c332bae83a14c733ae0ffb028@68.183.24.23:26656"

tendermint start --home ./mytestnet/node3 --proxy-app=kvstore --p2p.persistent-peers="71abf2272bcac2f63a5461a85d3a59d4964f239f@142.93.159.27:26656,733c2b6c5b090bd29223afff812cbed0a1fa49d7@142.93.172.101:26656,ef3df96b7c929adca315a7781623205d9b0a5138@174.138.31.61:26656,d909a1b375ae730c332bae83a14c733ae0ffb028@68.183.24.23:26656"
