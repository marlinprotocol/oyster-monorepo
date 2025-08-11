nix build .#packages.aarch64-linux.default.enclaves.governance.default

1st image https://gateway.pinata.cloud/ipfs/QmYT66P1E7iut6B2zHUTBLgxw8tVh1r1YXL3e26NZnKTom
{
  "HashAlgorithm": "Sha384 { ... }",
  "PCR0": "1485ce3672aa4731cd5bcaf0e889ae2f5158657ca0d175cafc56df1d3a13552f9b0fba3ce90ee52c7913d7b40dbe1479",
  "PCR1": "3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
  "PCR2": "580f6f0320afba1a5690c078a57e5e1ae745ad370b8ffcdcbf90fe514b8c7d48835122727563f8bba69aee82c3086c48"
}

2nd image https://8d496d360731.ngrok-free.app/image.eif
{
  "HashAlgorithm": "Sha384 { ... }",
  "PCR0": "7980d9042bfc3b30a4640aa0387cdd26fb19efc1b7b53f6e112216909251fa8eb131fcf26c9702843d6fc1b89830daec",
  "PCR1": "3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
  "PCR2": "ee52c90f26397b923859ccae7c81239f94f94f3181fe7f5c9d18a18d44fec420fbe686096f8756b47b9ad1bc46d4e4ef"
}

{
  "HashAlgorithm": "Sha384 { ... }",
  "PCR0": "87b9453540c2e88071d13cb0c1a507db5eae70ad2fe1a76c9f09b977a9826f403cdd687d5f90bd04a784106ecb41d14d",
  "PCR1": "3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
  "PCR2": "9ffa7f8de15e824fa44ccf2378677844de1eecfd2c113fd51a2c6779f00a2c3eb1c2dc23c76270bce0b9172fdd7d89d0"
}

{
  "HashAlgorithm": "Sha384 { ... }",
  "PCR0": "18e932a8d5a5f6b09f203767b23fc138af8884631b873af2312fa8e1cbd06247459b0f0823fc81e07a696869f98fa783",
  "PCR1": "3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
  "PCR2": "f0623f47eae2d72556988fed12ea2bcd47e21dc6c1dbc63bdddfb10aa4bd6ab25fe6fb27d6bc172d58defae99655ec3b"
}

{
  "HashAlgorithm": "Sha384 { ... }",
  "PCR0": "6aa6d86dd58137e29e3fd9f95fd2d5c8c9a2f3759c696db41452e0358e04bc2b038fad2c187746dc86e7cee73491d21b",
  "PCR1": "3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
  "PCR2": "18eff38788e9c80120c8b511e1c89019c88999730075a17361b62b73539a63f13c77b17efeec605beecc32dc4ee8b0ca"
}


# Debug
./cli/oyster-cvm/target/release/oyster-cvm deploy \
--wallet-private-key PRIV_KEY \
--image-url https://5d14f4a0b8a7.ngrok-free.app/image.eif \
--instance-type c6g.xlarge \
--duration-in-minutes 15 \
--init-params config/rpc_url:0:0:utf8:https://sepolia-rollup.arbitrum.io/rpc \
--init-params secrets/default_api_key:0:0:utf8:l86jFYjBFWZTQMRof96TpIGigjbZMUcr \
--init-params config/gov_contract:0:0:utf8:0x765134172aDeC674057E5D62653aC44288662061 \
--init-params params/proposal_id:0:0:utf8:0xed202dd20938ed6ed2e1a637987a28233c45ef3d1bedbbc52560952f3cb7b68f \
--init-params secrets/api_keys.json:0:0:file:./api_keys.json \
--init-params config/chain_ids.json:0:0:file:./chain_ids.json \
--init-params config/rpc_index.json:0:0:file:./rpc_index.json \
--debug

# Normal
./cli/oyster-cvm/target/release/oyster-cvm deploy \
--wallet-private-key PRIV_KEY \
--image-url https://5d14f4a0b8a7.ngrok-free.app/image.eif \
--instance-type c6g.xlarge \
--duration-in-minutes 15 \
--init-params config/rpc_url:0:0:utf8:https://arb-sepolia.g.alchemy.com/v2 \
--init-params secrets/default_api_key:0:1:utf8:abc123defaultkey \
--init-params config/gov_contract:1:0:utf8:0x1234567890abcdef \
--init-params params/proposal_id:1:0:utf8:0x0573C572DB4F4A205FF5D66E087AD4A1EFD6FC7B18E24D58A0E0544C9D287D1F \
--init-params params/start_ts:1:0:utf8:1723567200 \
--init-params params/data_hash:1:0:utf8:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef \
--init-params secrets/api_keys.json:0:1:file:./api_keys.json \
--init-params config/chain_ids.json:0:0:file:./chain_ids.json \
--init-params config/rpc_index.json:0:0:file:./rpc_index.json \


running python server for http
python3 -m http.server 8000
ngrok http 8000
