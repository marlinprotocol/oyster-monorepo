// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./interfaces/IClusterSelector.sol";
import "./ReceiverStaking.sol";
import "./interfaces/IClusterRewards.sol";

contract ClusterRewards is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    IClusterRewards  // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

//-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) onlyAdmin internal view override {}

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(
        address _admin,
        address _claimer,
        address _receiverStaking,
        bytes32[] memory _networkIds,
        uint256[] memory _rewardWeight,
        address[] memory _clusterSelectors,
        uint256 _totalRewardsPerEpoch
    )
        public
        initializer
    {
        require(
            _networkIds.length == _rewardWeight.length,
            "CRW:I-Each NetworkId need a corresponding RewardPerEpoch and vice versa"
        );
        require(
            _networkIds.length == _clusterSelectors.length,
            "CRW:I-Each NetworkId need a corresponding clusterSelector and vice versa"
        );

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _admin);

        _setupRole(CLAIMER_ROLE, _claimer);

        _updateReceiverStaking(_receiverStaking);

        uint256 _weight = 0;
        for(uint256 i=0; i < _networkIds.length; i++) {
            rewardWeight[_networkIds[i]] = _rewardWeight[i];
            require(_clusterSelectors[i] !=  address(0), "CRW:CN-ClusterSelector must exist");
            clusterSelectors[_networkIds[i]] = IClusterSelector(_clusterSelectors[i]);
            _weight += _rewardWeight[i];
            emit NetworkAdded(_networkIds[i], _rewardWeight[i], _clusterSelectors[i]);
        }
        totalRewardWeight = _weight;
        _changeRewardPerEpoch(_totalRewardsPerEpoch);
        payoutDenomination = 1e18;
    }

//-------------------------------- Initializer end --------------------------------//

//-------------------------------- Admin functions start --------------------------------//

    bytes32 public constant CLAIMER_ROLE = keccak256("CLAIMER_ROLE");
    bytes32 public constant FEEDER_ROLE = keccak256("FEEDER_ROLE");
    uint256 public constant RECEIVER_TICKETS_PER_EPOCH = 2**16;
    uint256 constant SWITCHING_PERIOD = 33 days;

    mapping(address => uint256) public clusterRewards;

    mapping(bytes32 => uint256) public rewardWeight;
    uint256 public totalRewardWeight;
    uint256 public totalRewardsPerEpoch;
    uint256 public payoutDenomination;

    mapping(uint256 => uint256) public rewardDistributedPerEpoch;
    uint256 public latestNewEpochRewardAt;
    uint256 public rewardDistributionWaitTime;

    mapping(address => mapping(uint256 => uint256)) public ticketsIssued;
    mapping(bytes32 => IClusterSelector) public clusterSelectors; // networkId -> clusterSelector
    ReceiverStaking public receiverStaking;

    event NetworkAdded(bytes32 networkId, uint256 rewardPerEpoch, address clusterSelector);
    event NetworkRemoved(bytes32 networkId);
    event NetworkUpdated(bytes32 networkId, uint256 updatedRewardPerEpoch, address clusterSelector);
    event ClusterRewarded(bytes32 networkId);
    event ReceiverStakingUpdated(address receiverStaking);
    event RewardPerEpochChanged(uint256 updatedRewardPerEpoch);
    event RewardDistributionWaitTimeChanged(uint256 updatedWaitTime);
    event TicketsIssued(bytes32 indexed networkId, uint256 indexed epoch, address indexed user);

    modifier onlyFeeder() {
        require(hasRole(FEEDER_ROLE, _msgSender()), "only feeder");
        _;
    }

    function addNetwork(bytes32 _networkId, uint256 _rewardWeight, address _clusterSelector) external onlyAdmin {
        require(rewardWeight[_networkId] == 0, "CRW:AN-Network already exists");
        require(_clusterSelector !=  address(0), "CRW:AN-ClusterSelector must exist");
        rewardWeight[_networkId] = _rewardWeight;
        IClusterSelector networkClusterSelector = IClusterSelector(_clusterSelector);
        require(networkClusterSelector.START_TIME() == receiverStaking.START_TIME(), "CRW:AN-start time inconsistent");
        require(networkClusterSelector.EPOCH_LENGTH() == receiverStaking.EPOCH_LENGTH(), "CRW:AN-epoch length inconsistent");

        clusterSelectors[_networkId] = networkClusterSelector;
        totalRewardWeight += _rewardWeight;
        emit NetworkAdded(_networkId, _rewardWeight, _clusterSelector);
    }

    function removeNetwork(bytes32 _networkId) external onlyAdmin {
        uint256 networkWeight = rewardWeight[_networkId];
        require(address(clusterSelectors[_networkId]) != address(0), "CRW:RN-Network doesnt exist");
        delete rewardWeight[_networkId];
        delete clusterSelectors[_networkId];
        totalRewardWeight -= networkWeight;
        emit NetworkRemoved(_networkId);
    }

    function updateNetwork(bytes32 _networkId, uint256 _updatedRewardWeight, address _updatedClusterSelector) external onlyAdmin {
        uint256 networkWeight = rewardWeight[_networkId];
        require(_updatedClusterSelector !=  address(0), "CRW:UN-ClusterSelector must exist");
        address currentClusterSelector = address(clusterSelectors[_networkId]);
        require(currentClusterSelector != address(0), "CRW:UN-Network doesnt exist");

        if(_updatedClusterSelector != currentClusterSelector) {
            IClusterSelector networkClusterSelector = IClusterSelector(_updatedClusterSelector);
            require(networkClusterSelector.START_TIME() == receiverStaking.START_TIME(), "CRW:UN-start time inconsistent");
            require(networkClusterSelector.EPOCH_LENGTH() == receiverStaking.EPOCH_LENGTH(), "CRW:UN-epoch length inconsistent");
            clusterSelectors[_networkId] = IClusterSelector(_updatedClusterSelector);
        }

        rewardWeight[_networkId] = _updatedRewardWeight;
        totalRewardWeight = totalRewardWeight - networkWeight + _updatedRewardWeight;
        emit NetworkUpdated(_networkId, _updatedRewardWeight, _updatedClusterSelector);
    }

    /// @dev any updates to startTime or epoch length in receiver staking must also be reflected in all clusterSelectors
    function updateReceiverStaking(address _receiverStaking) external onlyAdmin {
        _updateReceiverStaking(_receiverStaking);
    }

    function _updateReceiverStaking(address _receiverStaking) internal {
        receiverStaking = ReceiverStaking(_receiverStaking);
        emit ReceiverStakingUpdated(_receiverStaking);
    }

    function changeRewardPerEpoch(uint256 _updatedRewardPerEpoch) external onlyAdmin {
        _changeRewardPerEpoch(_updatedRewardPerEpoch);
    }

    function _changeRewardPerEpoch(uint256 _updatedRewardPerEpoch) internal {
        totalRewardsPerEpoch = _updatedRewardPerEpoch;
        emit RewardPerEpochChanged(_updatedRewardPerEpoch);
    }

    function updateRewardWaitTime(uint256 _updatedWaitTime) external onlyAdmin {
        _updateRewardWaitTime(_updatedWaitTime);
    }

    function _updateRewardWaitTime(uint256 _updatedWaitTime) internal {
        rewardDistributionWaitTime = _updatedWaitTime;
        emit RewardDistributionWaitTimeChanged(_updatedWaitTime);
    }

//-------------------------------- Admin functions end --------------------------------//

//-------------------------------- User functions start --------------------------------//

    function feed(
        bytes32 _networkId,
        address[] calldata _clusters,
        uint256[] calldata _payouts,
        uint256 _epoch
    ) external onlyFeeder {
        require(receiverStaking.START_TIME() + SWITCHING_PERIOD + 1 days > block.timestamp, "CRW:F-Invalid method");
        uint256 rewardDistributed = rewardDistributedPerEpoch[_epoch];
        if(rewardDistributed == 0) {
            require(
                block.timestamp > latestNewEpochRewardAt + rewardDistributionWaitTime,
                "CRW:F-Cant distribute reward for new epoch within such short interval"
            );
            latestNewEpochRewardAt = block.timestamp;
        }
        uint256 currentPayoutDenomination = payoutDenomination;
        uint256 networkRewardWeight = rewardWeight[_networkId];
        uint256 currentTotalRewardsPerEpoch = totalRewardsPerEpoch*1 days/receiverStaking.EPOCH_LENGTH()*networkRewardWeight/totalRewardWeight;
        for(uint256 i=0; i < _clusters.length; i++) {
            uint256 clusterReward = (currentTotalRewardsPerEpoch * _payouts[i]) / currentPayoutDenomination;
            rewardDistributed = rewardDistributed + clusterReward;
            clusterRewards[_clusters[i]] = clusterRewards[_clusters[i]] + clusterReward;
        }
        require(
            rewardDistributed <= currentTotalRewardsPerEpoch,
            "CRW:F-Reward Distributed  cant  be more  than totalRewardPerEpoch"
        );
        rewardDistributedPerEpoch[_epoch] = rewardDistributed;
        emit ClusterRewarded(_networkId);
    }

    function _processReceiverTickets(address _receiver, uint256 _epoch, address[] memory _selectedClusters, uint16[] memory _tickets, uint256 _totalNetworkRewardsPerEpoch, uint256 _epochTotalStake, uint256 _epochReceiverStake) internal {
        require(!_isTicketsIssued(_receiver, _epoch), "CRW:IPRT-Tickets already issued");

        unchecked {
            require(_selectedClusters.length <= _tickets.length + 1, "CRW:IPRT-Tickets length not matching selected clusters");
            uint256 _rewardShare = _totalNetworkRewardsPerEpoch * _epochReceiverStake / _epochTotalStake;
            uint256 _totalTickets;
            uint256 i;
            for(; i < _selectedClusters.length - 1; ++i) {
                // cant overflow as max supply of POND is 1e28, so max value of multiplication is 1e28*2^16 < uint256
                // value that can be added  per iteration is < 1e28*2^16/2^16, so clusterRewards for cluster cant overflow
                clusterRewards[_selectedClusters[i]] += _rewardShare * uint256(_tickets[i]) / RECEIVER_TICKETS_PER_EPOCH;

                // cant overflow as tickets[i] <= 2^16
                _totalTickets += uint256(_tickets[i]);
            }
            require(RECEIVER_TICKETS_PER_EPOCH >= _totalTickets, "CRW:IPRT-Total ticket count invalid");
            clusterRewards[_selectedClusters[i]] += _rewardShare * uint256(RECEIVER_TICKETS_PER_EPOCH - _totalTickets)/RECEIVER_TICKETS_PER_EPOCH;
        }

        _markAsIssued(_receiver, _epoch);
    }

    function _isTicketsIssued(address _receiver, uint256 _epoch) internal view returns(bool) {
        unchecked {
            uint256 _index = _epoch/256;
            uint256 _pos = _epoch%256;
            uint256 _issuedFlags = ticketsIssued[_receiver][_index];
            return (_issuedFlags & 2**(255-_pos)) != 0;
        }
    }

    function isTicketsIssued(address _receiver, uint256 _epoch) public view returns(bool) {
        return _isTicketsIssued(_receiver, _epoch);
    }

    function _markAsIssued(address _receiver, uint256 _epoch) internal {
        unchecked {
            uint256 _index = _epoch/256;
            uint256 _pos = _epoch%256;
            uint256 _issuedFlags = ticketsIssued[_receiver][_index];
            ticketsIssued[_receiver][_index] = _issuedFlags | 2**(255-_pos);
        }
    }

    function issueTickets(bytes32 _networkId, uint24[] calldata _epochs, uint16[][] calldata _tickets) external {
        uint256 numberOfEpochs = _epochs.length;
        require(numberOfEpochs == _tickets.length, "CRW:MIT-invalid inputs");
        unchecked {
            for(uint256 i=0; i < numberOfEpochs; ++i) {
                uint256 _totalNetworkRewardsPerEpoch = getRewardForEpoch(_epochs[i], _networkId);
                (uint256 _epochTotalStake, uint256 _currentEpoch) = receiverStaking.getEpochInfo(_epochs[i]);
                require(_epochs[i] < _currentEpoch, "CRW:IT-Epoch not completed");
                address[] memory _selectedClusters = clusterSelectors[_networkId].getClusters(_epochs[i]);
                (uint256 _epochReceiverStake, address _receiver) = receiverStaking.balanceOfSignerAt(msg.sender, _epochs[i]);
                _processReceiverTickets(_receiver, _epochs[i], _selectedClusters, _tickets[i], _totalNetworkRewardsPerEpoch, _epochTotalStake, _epochReceiverStake);
                emit TicketsIssued(_networkId, _epochs[i], msg.sender);
            }
        }
    }

    function issueTickets(bytes calldata _ticketInfo) external {
        (
            bytes32 _networkId, 
            uint256 _fromEpoch, 
            uint256 _noOfEpochs,
            uint16[][] memory _tickets
        ) = _parseTicketInfo(_ticketInfo);

        ReceiverStaking _receiverStaking = receiverStaking;
        require(_fromEpoch + _noOfEpochs <= _receiverStaking.getCurrentEpoch(), "CRW:ITC-Epochs not completed");

        uint256[] memory _stakes = _receiverStaking.totalSupplyAtRanged(_fromEpoch, _noOfEpochs);
        (uint256[] memory _balances, address _receiver) = _receiverStaking.balanceOfSignerAtRanged(msg.sender, _fromEpoch, _noOfEpochs);
        address[][] memory _selectedClusters = clusterSelectors[_networkId].getClustersRanged(_fromEpoch, _noOfEpochs);
        uint256 _epochLength = _receiverStaking.EPOCH_LENGTH();
        uint256 _totalNetworkRewardsPerEpoch;

        unchecked {
            for(uint256 i=0; i < _noOfEpochs; ++i) {
                _totalNetworkRewardsPerEpoch = _getRewardForEpoch(_fromEpoch, _networkId, _epochLength);
                _processReceiverTickets(_receiver, _fromEpoch, _selectedClusters[i], _tickets[i], _totalNetworkRewardsPerEpoch, _stakes[i], _balances[i]);
                emit TicketsIssued(_networkId, _fromEpoch, msg.sender);
                ++_fromEpoch;
            }
        }
    }

    function _parseTicketInfo(bytes memory ticketInfo) internal view returns(
        bytes32 networkId,
        uint256 fromEpoch,
        uint256 noOfEpochs,
        uint16[][] memory tickets
    ) {
        // Ticket Structure
        // |--NetworkId(256 bits)--|--FromEpoch(32 bits)--|--N*Ticket(16 bits)--|

        uint256 length;
        bytes32 currentWord;
        assembly {
            length :=  mload(ticketInfo)
            networkId := mload(add(ticketInfo, 0x20))
            currentWord := mload(add(ticketInfo, 0x40))
        }
        fromEpoch = uint256(currentWord >> 224);
        unchecked {
            require(length >= 36 && (length - 36)%8 == 0, "CR:IPTI-invalid ticket info encoding");
            noOfEpochs = (length - 36)/8; // 32 (networkId) + 4 (fromEpoch) / 2(tickets) / 4(tickets per epoch)
            // +1 because of slight overflow on last word
            uint256 noOfWords = length/32;
            tickets = new uint16[][](noOfEpochs);
            uint256 clustersToSelect = clusterSelectors[networkId].NUMBER_OF_CLUSTERS_TO_SELECT();
            // revert due to memory expansion overflow in case of underflow
            tickets[0] = new uint16[](clustersToSelect - 1);
            (uint256 _currentEpochIndex, uint256 _currentTicketIndex) = _extractTickets(currentWord, 2, 0, 0, tickets);

            for(uint256 i=1; i < noOfWords; ++i) {
                assembly {
                    currentWord := mload(add(ticketInfo, add(0x40, mul(0x20, i))))
                }
                (_currentEpochIndex, _currentTicketIndex) = _extractTickets(currentWord, 0, _currentEpochIndex, _currentTicketIndex, tickets);
            }
        }
    }

    function _extractTickets(
        bytes32 word, 
        uint256 startIndex, 
        uint256 currentEpochIndex, 
        uint256 currentTicketIndex,
        uint16[][] memory tickets
    ) internal pure returns(uint256, uint256) {
        unchecked {
            for(uint256 i = startIndex; i < 16; ++i) {
                tickets[currentEpochIndex][currentTicketIndex] = uint16(uint256(word >> (256 - (i + 1)*16)));
                currentTicketIndex++;

                if(currentTicketIndex > tickets[currentEpochIndex].length - 1) {
                    if(currentEpochIndex == tickets.length - 1) return (currentEpochIndex, currentTicketIndex);
                    currentEpochIndex++;
                    tickets[currentEpochIndex] = new uint16[](tickets[currentEpochIndex-1].length);
                    currentTicketIndex = 0;
                }
            }
        }
        return (currentEpochIndex, currentTicketIndex);
    }

    function issueTickets(bytes32 _networkId, uint24 _epoch, uint16[] memory _tickets) public {
        (uint256 _epochTotalStake, uint256 _currentEpoch) = receiverStaking.getEpochInfo(_epoch);

        require(_epoch < _currentEpoch, "CRW:IT-Epoch not completed");

        address[] memory _selectedClusters = clusterSelectors[_networkId].getClusters(_epoch);

        uint256 _totalNetworkRewardsPerEpoch = getRewardForEpoch(_epoch, _networkId);

        (uint256 _epochReceiverStake, address _receiver) = receiverStaking.balanceOfSignerAt(msg.sender, _epoch);
        _processReceiverTickets(_receiver, _epoch, _selectedClusters, _tickets, _totalNetworkRewardsPerEpoch, _epochTotalStake, _epochReceiverStake);

        emit TicketsIssued(_networkId, _epoch, msg.sender);
    }

    function claimReward(address _cluster) external onlyRole(CLAIMER_ROLE) returns(uint256) {
        uint256 pendingRewards = clusterRewards[_cluster];
        if(pendingRewards > 1) {
            uint256 rewardsToTransfer = pendingRewards - 1;
            clusterRewards[_cluster] = 1;
            return rewardsToTransfer;
        }
        return 0;
    }

    function _getRewardForEpoch(uint256 _epoch, bytes32 _networkId, uint256 _epochLength) internal view returns(uint256) {
        if(_epoch < SWITCHING_PERIOD/_epochLength) return 0;
        return (totalRewardsPerEpoch * rewardWeight[_networkId]) / totalRewardWeight;
    }

    function getRewardForEpoch(uint256 _epoch, bytes32 _networkId) public view returns(uint256) {
        return _getRewardForEpoch(_epoch, _networkId, receiverStaking.EPOCH_LENGTH());
    }

//-------------------------------- User functions end --------------------------------//
}
