# Init_params input
--init-params rpc_url:0:0:utf8:https://arb-sepolia.g.alchemy.com/v2 \
--init-params default_api_key:0:1:utf8:l86jFYjBFWZTQMRof96TpIGigjbZMUcr \
--init-params gov_contract:1:0:utf8:0xF27C5d12e12E53a63A146709DBb78619dd0EEA00 \
--init-params proposal_id:1:0:utf8:0xeaad6933228febe9dd393f9b2c4006eac7ff1f5f49e8332f279bdd3412f32717 \
--init-params start_ts:1:0:utf8:1753152991 \
--init-params data_hash:1:0:utf8:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
--init-params api_keys.json:0:1:file:./api_keys.json \
--init-params chain_ids.json:0:0:file:./chain_ids.json \
--init-params rpc_index.json:0:0:file:./rpc_index.json

## Json files
So we have this from init_params

// api_keys.json 
["key1", "key2", "key3", "key4"]

// chain_ids.json
[42161, 10, 10, 137]

// rpc_index.json
[0, 0, 1, 0]

now I call get_network_list, which will give
[42161, 10, 137]
[[rpc_url1],[ rpc_url2, rpc_url3], [rpc_url]]

I create multiple rpc's per chain
[42161] -> [rpc_url1/api_key1]
[10] -> [[rpc_url2/api_key2, rpc_url3/api_key3]
[137] -> [rpc_url4/api_key4]


getNetworkList()):
{
  "42161": ["https://arb-mainnet.alchemy.com/v2"],
  "10": ["https://opt-mainnet.infura.io/v3", "https://opt.alchemy.com/v2"],
  "137": ["https://polygon-rpc.com"]
}

