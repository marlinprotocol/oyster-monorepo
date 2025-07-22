// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {GovernanceInteraction} from "./GovernanceInteraction.s.sol";
import {IGovernanceTypes} from "../../../src/governance/interfaces/IGovernanceTypes.sol";
import {console} from "forge-std/console.sol";


contract SetGovernancePCRConfig is GovernanceInteraction {

    struct PCR {
        bytes pcr0;
        bytes pcr1;
        bytes pcr2;
    }

    PCR public pcr;


    constructor() {
        pcr = PCR({
            /* 21/07/2025 Testnet e2e ver. */
            pcr0: hex"759bfd91b6a6e5ff824cd31a7736ae6a36b652cd96ca81d3fc4afb58e25d22d739af7c53f8720fd162a433aaabc29ea6",
            pcr1: hex"3d9be02ba042fe48bc94881586fd57f6006260f05f7b56ed4e14cac66ab03b1f755825f334aa4b5a4b14cddc7a56fb32",
            pcr2: hex"922659ff62cae9aaf321ac5d93537587618a22dbbb923ff854014cdb14aa77686d74980c4dc8fa1250b2d2149bab8b41"
        });
    }

    function run() external {
        setPCRConfig();

        bytes32 imageId;
        IGovernanceTypes.PCR memory currentPCRConfig;
        (currentPCRConfig, imageId) = governance.pcrConfig();

        console.log("PCR Config set successfully.");
        console.log(" ");
        console.log("PCR0: ");
        console.logBytes(currentPCRConfig.pcr0);
        console.log("PCR1: ");
        console.logBytes(currentPCRConfig.pcr1);
        console.log("PCR2: ");
        console.logBytes(currentPCRConfig.pcr2);
        console.log(" ");
    }

    function setPCRConfig() public {
        vm.startBroadcast();
        governance.setPCRConfig(pcr.pcr0, pcr.pcr1, pcr.pcr2);
        vm.stopBroadcast();
    }
}
