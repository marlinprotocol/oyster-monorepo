// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "../../src/kms/KmsVerifiable.sol";

contract KmsVerifiableScript is Script {
    function run() external returns (KmsVerifiable) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        bytes32 [] memory _imageIds = new bytes32[](0);
        KmsVerifiable kmsVerifiable = new KmsVerifiable(_imageIds);
        vm.stopBroadcast();
        console.log("Deployed to:", address(kmsVerifiable));

        return kmsVerifiable;
    }
}
