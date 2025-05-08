import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const walletClient = createWalletClient({
  chain: foundry,
  transport: http(""),
});

const DOMAIN = {
  name: 'marlin.oyster.AttestationVerifier',
  version: '1',
};

const TYPES = {
  Attestation: [
    { name: 'imageId', type: 'bytes32' },
    { name: 'timestampMs', type: 'uint64' },
    { name: 'publicKey', type: 'bytes' },
    { name: 'userData', type: 'bytes' },
  ],
};

const account =
  privateKeyToAccount("0xdc18850da3d958ffe330e8d87937622bb33964972c7030857b19369a6e81ed3d");

const signature = await walletClient.signTypedData({
  account,
  domain: DOMAIN,
  types: TYPES,
  primaryType: 'Attestation',
  message: {
    imageId: "0x0000000000000000000000000000000000000000000000000000000000000002",
    timestampMs: 0x4e43046b,
    publicKey: "0x9f82020b6e9431e8abcc0f1ce313248a10bc9e96e59b720dc3653398496c3c52dea402c5ef3a6780ccf1f0aeeaa68ae4e3f132496d011df322e84b171e82750d",
    userData: "0x12345678",
  }
});

console.log('Generated signature:', signature);
console.log('Pubkey:', account.publicKey);
