// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IArbGasInfo {
    function getPricesInArbGas() external view returns (uint, uint, uint);
}

contract ArbGasInfo is IArbGasInfo {
    uint256 public perL2Tx;
    uint256 public gasForL1Calldata;
    uint256 public storageArbGas;

    constructor() {}

    function setPrices(uint256 _perL2Tx, uint256 _gasForL1Calldata, uint256 _storageArbGas) public {
        perL2Tx = _perL2Tx;
        gasForL1Calldata = _gasForL1Calldata;
        storageArbGas = _storageArbGas;
    }

    function getPricesInArbGas() external view override returns (uint, uint, uint) {
        return (perL2Tx, gasForL1Calldata, storageArbGas);
    }
}