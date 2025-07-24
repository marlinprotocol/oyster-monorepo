// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IInflationRewardsManager {
    function notifyOutputSubmission(address _operator) external;

    function updateInflationRewards(
        address _operator,
        address _delegator,
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        bool _isDelegation
    ) external;

    // function delegate(
    //     address _operator,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external;

    // function undelegate(
    //     address _operator,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external;

    // function withdrawRewards(address _operator,address _delegator) external;
}