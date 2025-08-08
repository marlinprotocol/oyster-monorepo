// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IInflationRewardsManager {
    function notifyOutputSubmission(address _executor) external;

    function updateInflationRewards(
        address _executor,
        address _delegator,
        bytes32[] memory _tokens,
        uint256[] memory _amounts,
        bool _isDelegation
    ) external;

    // function delegate(
    //     address _executor,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external;

    // function undelegate(
    //     address _executor,
    //     address _delegator,
    //     bytes32[] memory _tokens,
    //     uint256[] memory _amounts
    // ) external;

    // function withdrawRewards(address _executor,address _delegator) external;
}