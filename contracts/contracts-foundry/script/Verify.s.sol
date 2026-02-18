// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {KmsRoot} from "../src/kms/KmsRoot.sol";
import {IAttestationVerifier} from "../src/attestation/IAttestationVerifier.sol";

contract Verify is Script {
    KmsRoot public kmsRoot;

    function setUp() public {
        kmsRoot = KmsRoot(0xF01706d56AcA3764d332D12E0EB6E5DdB21Ca0cA);
    }

    function run() public {
        vm.startBroadcast();

        kmsRoot.verify(
            hex"73c457ba257b21abcae9116f35180cc29963642cead5dcca64cc04e63b9a5afe16206e012dfc8b1d1e3c488eef155eeaf45487524cd10b7b1d77367f2c7fe97a52c1bb1328d78c0995122e568918cd7631fafb12dbc8fcc2ce980d4a655a65b5ec0176242f896bb9708af5f8a48c2dcf604ad60404aa4c7d9ae1a0a8aeb7c64bbc171fba27323bf8f56f68f7815ce732fb6e10fea0524f15b863a25116ca71da3c267d9a210e39b449b11ffdb74e0bba39977b4a72da5568d6c503f679ef62660e0126350456149c9194a8e96b9287194640c2dea3721fd59cce3850c8842aea68c950ce23056cb75941e97275277dac3a60475d8e1b2d7afff71e1472d3b511ab678a0d",
        IAttestationVerifier.Attestation(
            0xe703044b4e136bde71369a0b00d11052b594592d8ebae8567e0859177768b7f2,
            0x0000019994d18918,
            hex"f63b67826b51a15fa5eb8948cec1049f24ad3d36113e06aaadaa9824c8d38f6d45dd96c97621f7a96b6b7cba32604c914c1e38241fa8dc8d3443a06ce28ad579",
            hex""
        ));

        vm.stopBroadcast();
    }
}
