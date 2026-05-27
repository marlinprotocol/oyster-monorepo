# Getting started

This repo contains token as well as protocol related smart contracts used in Marlin. 

1. Spin up an instance for running or testing the contracts. 
2. Make sure you have docker installed and execute the following command:
```
sh start.sh
```
3. If you are not using docker, make sure you have **truffle**, **node** 10.x installed on your device.
4. Use the following commands to compile and test the contracts.
```
truffle compile;
ganache-cli -a 51;
truffle test;
```

# POND token

POND is a standard ERC-20 token contract with a total supply of 10 billion.

# MPOND token

MPOND is Marlin's governance and staking token. It can used to create and vote on proposals. It is also required to run a Marlin node.

## Specs
1. Total supply of MPOND is 10,000.
2. MPOND can be used to vote and create proposals, where 1 MPOND tokens = 1 vote (votes are fungible as tokens).
3. MPOND tokens delegated to other users will be locked.
4. Direct MPOND transfers will be locked except for whitelisted addresses (like the bridge and stakedrop contracts). Until universal transfers are enabled, only transfers to/from whitelisted addresses are possible.
5. MPOND can be converted to POND via the bridge.
6. If delegated, users will first have to undelegate the tokens before being able to make a transfer.

## Contract
Notable functions of the contract are described below:
* `addWhiteListAddress**(address _address)` adds a new address that is whitelisted for transfers and can only be invoked by admin.
* `enableAllTransfers()` enables anyone to transfers MPOND and can be only invoked by admin.
* `balanceOf`, `transfer`, `approve`, `transferFrom` functions, have same signatures as that of standard ERC20 Token contract
* Can delegate tokens to any address using `delegate(address delegatee, uint96 amount)` where `delegatee` is the address of the delegatee and `amount` is number of token to be delegated.
* To undelegate the tokens from any address use `undelegate(address delegatee, uint96 amount)`.
* `getCurrentVotes(address account)` returns the current votes that have been delegated to `account`.
* `getPriorVotes(address account, uint256 blockNumber)` returns the votes the delegated to `account` at a given `blockNumber`.

# Governance

## Specs
1. The governance contracts will be able to create any number of proposals.
2. Any users who has 1 or more delegated MPOND should be able to successfully create a proposal.
3. An address can only have **1 Active proposal** at a time.
4. A proposal when created is in a Pending state by default. After 2 days it changes to an **Active** state.
5. Any address with MPOND, owned or delegated, can cast vote on any proposal. The number of votes an address is eligible for depends on its MPOND balance at the time of creation of the proposal.
6. The voting period is open for 3 days.
7. If the proposal has gathered atleast 8000 MPOND votes in 3 days, the state changes from **Active** to **Succeeded**.
8. If the proposal fails to gather sufficient votes, the state changes to **Defeated**
9. **Succeeded** can be changed to **Queued** state by a contract call.
10. A **Queued** proposal will be locked for 2 days. Within this time, the admin has right to **Reject** the proposal. If **Unrejected**, the proposal is **Executed**.

Governance comprises of three contracts
* MPOND token contract
* GovernorAlpha
* Timelock

## MPOND token
Token contract as described above.

## Governor Alpha
* A proposal can be made by holding 1 MPOND (which is also equivalent to vote) using the method `function propose(address[] memory targets, uint256[] memory values, string[] memory signatures, bytes[] memory calldatas, string memory description)` where 
    * `targets` refer to the target contracts that need to be updated
    * `values`, `signature`, `calldata` correspond to functions being called
    * `description` is an optional field that can be used to define the proposal
* When in **Active** state, a proposal can be voted on using method `castVote(uint256 proposalId, bool support)` where
    * `proposalId` is the id of the proposal
    * `support` is the boolean parameter where `support=true` indicates that the address has voted **for** the proposal
* A **Succeeded** Proposal can be passed to **Queued** state. When in **Queued** state it can be rejected by the admin within 3 days. To queue a proposal, call function `queue(uint256 proposalId)` where `proposalId` is the id of the proposal.
* A **Queued Proposal** can be executed using `execute(uint256 proposalId)` where `proposalId` is the id of the existing proposal.

## Timelock
Timelock contract is used for locking the Proposal in various stage of its cycle. It is used internally within GovernorAlpha.

# Stake Drop Contracts

The stake-drop happens via set of 3 oracles and a distribution contract. The purpose of the whole set of contracts is to distribute the mPond token to all registered-delegators who have been staking with the whitelisted validators.

### The oracles part of stake-drop are
* AddressRegistry.sol
* ValidatorRegistry.sol
* StakeRegistry.sol

### The distribution contract is 
* Distribution.sol

## Oracles
All the oracles are derived from a contract **StandardOracle.sol**. This act as a address based access registry for all the child contracts.

### StandardOracle
* Contains the mapping of addresses that have to access to pump the data to the contract. Mapping is defined as `mapping(address => bool) sources`
* The address that deploys the contract is a `source` by default
* Only an existing source can add a new source using method `addSource(address _newSource)` where `_newSource` is the address of the new source
* A source can renounce itself using method `renounceSource()`

### Validator Registry
ValidatorRegistry is derived from StandardOracle
#### Specs and contract
* Contains the mapping of whitelisted validators for every era in     `mapping(uint256 => mapping(bytes32 => bool)) validators` i.e.
```
isValidator = validators[era][validatorAddressHash]
//isValidator will be true if the particular address hash is validator in that era
```
* Validator Address's hash is used in the mapping, not the address itself. The hash can be computed using 
```
validatorAddressHash = web3.utils.keccak256(stakingAddress)
```

* Validators can be adding using `addValidator(uint256 epoch, bytes32 validatorAddressHash)` where 
    * `epoch` is the epoch/era number of the staking chain
    * `validatorAddressHash` is the hash of the validator's address
* Validator's can also be added in bulk using `addValidatorsBulk(uint256 epoch, bytes32[] memory validators)` where 
    * `epoch` is the epoch/era number of the staking chain
    * `validators` array is the list of validators in the array.
    * Note: *`addValidatorsBulk` will revert if even one of the validatorHash in the array is repeated*
* After adding validators, the list has to be frozen. This is prevent any further adding of validators accidentally. This is done via `freezeEpoch(uint256 epoch)` where
    * `epoch` is the epoch/era number of the staking chain
* Whenever a validator is successfully added `AddValidator**(uint256 indexed, bytes32 indexed)` event is emitted where
    * `uint256`, the first indexed param of event, is `epoch` number of the staking chain
    * `bytes32`, the second indexed param of event, is the `keccak256` hash of the validator address.

### Address Registry
AddressRegistry is derived from StandardOracle

#### Specs and contract
* Contains mapping of delegator's address hash and equivalent ethereum address. `mapping(bytes32 => address) addressList`, 
    * where `bytes32` is the `keccak256` hash of the delegator's `address`
* Also contains ethereum address and it's equivalent delegator's address hash `mapping(address => bytes32) reverseMap`, 
    * where `bytes32` is the `keccak256` hash of the delegator's `address`
* Address can added via one of the `source` address of the oracle using `addAddress(bytes32 stakingAddressHash, address ethereumAddress)` 
    * where `stakingAddressHash` is the `keccak256` hash of the delegator's `ethereumAddress`
* After successfull adding, event `AddressRegistered(bytes32 indexed, address indexed)` is emited where
    * `bytes32`, first param of the event, is the hash of the delegator's `stakingAddress`
    * `address`. second param of the event, is the eth/reward address of the delegator
* Address can be removed using `removeAddress**(bytes32 stakingAddressHash)` 
    * where `stakingAddressHash` is the `keccak256` is the hash of the delegator staking `address`

### Stake Registry
StakeRegistry is derived from StandardOracle

#### Specs and contract
* Stakes can be added only after validators list have been frozen the ValidatorRegistry contract
* Stakes can be added only after total stakes in the era have been updates. Method `addTotalStakeForEpoch(uint256 epoch, uint256 amount)`
    * where `epoch` is the epoch/era number of the respective chain
    * `amount` is the total stake put in that era
* Stakes can be added using method `addStake(uint256 epoch, bytes32 stakingAddressHash, bytes32 validatorAddressHash, uint256 amount)` 
    * where `epoch` is the epoch/era number of the respective chain
    * where `stakingAddressHash` is the `keccak256` hash of the delegator's address
    * `validatorAddressHash` is the `keccak256` hash of validator's address
    * `amount` is the delegator's stake
* Stakes can be added in bulk using `addStakeBulk(uint256 epoch, bytes32[] memory stakingAddresses, bytes32[] memory validatorAddresses, uint256[] memory amounts)`
    * where `epoch` is the epoch/era number of the respective chain
    * where `stakingAddresses` is the array of `keccak256` hashes of stakingAddresses of delegators
    * where `validatorAddresses` is the array of `keccak256` hashes of validators, matched against the arity of the `stakingAddresses` 
    * where `amounts` is the array of delegator's stake 
    * Note: *Only stakes which are delegated to whitelisted validators are rewarded*.
* On successful adding of stake `StakeAdded(uint256, bytes32, bytes32, uint256)` event is emitted where
    * `uint256`, first parameter of the event, is epoch/era number corresponding to the staking chain
    * `bytes32`, the second parameter of the event, is the delegator staking address `keccak256` hash
    * `bytes32`, thrid paramter of the event, is the validator's address hash corresponding w,r,t arity match.
    * `uint256`, the fourth paramter of the event, is the delegators stake in that era/epoch
* If the validatorAddress is not whitelisted, adding the stake is skipped. Event `StakeSkipped(uint256, bytes32, bytes32, uint256)` event is emitted. The event is similar to `StakeAdded`
* `rewardPerEpoch` is the total reward that is distributed to all delegators. This can only be changed by governance. 
* `mapping(bytes32 => uint256) rewardPerAddress` stores the reward that has to dispensed to every user where
    * `bytes32` refers to the `keccak256` hash of the delegators staking address
    * `uint256` is the reward earned that corresponding address hash

### Distribution
The contract depends on the above three oracles.

#### Specs and contract
* `mapping(bytes32 => uint256) claimedBalances` contains the balances withdrawn the delegator's address hash, where
    * `bytes32` refers to the delegator's address hash
    * `uint256` refers to the claimed/withdrawn balance
* `getUnclaimedAmount()` returns the available balance that can be dispensed. The function fetches the address hash from `AddressRegistry.sol` contract, where bidirectional map of `address hash` and `reward address` are stored
* `claimAmount()` transfers the reward tokens to the user.

# Bridge

Marlin uses POND and MPOND tokens as part its token economy. 

POND is a simple ERC20 token which is transferable and can be delegated to Marlin nodes. Network rewards for work done by validators is received in POND.

MPOND is initially non-transferable between users. They are used in governance and are also required to run nodes.

A bridge contract is used to convert between MPOND and POND. 1 MPOND can exchanged for 1 million POND tokens and vice-versa via the bridge.  

## POND to MPOND

POND can be converted to MPOND by sending POND to the bridge and an equivalent number of MPOND (#POND/1m) is received on the same address while burning the POND tokens sent.

## MPOND to POND

The bridge also allows conversion of MPOND to an equivalent number of POND (#POND X 1m). However, the conversion is a bit nuanced and not instantaneous as above. The mechanism is described below.

A request can be made on the bridge to convert a certain number of MPOND (say P). After transfer request is made, there is a wait time of W blocks (set at approximately 6 months initially) before a conversion can be attempted. During the wait time, MPOND can still be used towards staking and governance. After the wait time, a fraction L of P MPOND can be sent to the bridge for conversion.

Parameter W and L are both controlled by governance. These parameters make sure that there are always enough MPOND locked to ensure that the security of the network and its governance is not compromised. After every W blocks, $L$ of P MPOND requested initially can be sent to the bridge for conversion. That is, if W and $L$ remain constant, the user can convert all the requested MPOND to POND in $\lceil{\frac{100}{L}}\rceil*W$ blocks.

A series of scenarios and expected results of calls made to the Bridge are illustrated in the table below.

| Timespan | MPOND balance | Call Maxima | Result | Maxima mapping   | Maxima used mapping | Liquidity | Effective Liq. (calculated) | Call convert | Result |
|----------|---------------|-------------|--------|------------------|---------------------|-----------|-----------------------------|--------------|--------|
| Day -1   |          1000 |             |        | {-1:0}           |                     |        0% |                             |              |        |
| Day 0    |          1000 |        1100 | reject | {-1:0}           |                     |        0% |                             |              |        |
| Day 0    |          1000 |         900 | accept | {0: 900}         | {0:0}               |        0% |                             |              |        |
| Day 30   |          1000 |          50 | accept | {0: 900, 30: 50} | {0:0, 30:0}         |        0% |                             |              |        |
| Day 31   |          1000 |         100 | reject | {0: 900, 30: 50} |                     |           |                             |              |        |
| Day 180  |          1000 |             |        | {0: 900, 30: 50} | {0:0, 30:0}         |        0% |                             | 950, 0       | reject |
| Day 180  |          1000 |             |        | {0: 900, 30: 50} | {0:0, 30:0}         |       10% |                             |              |        |
| Day 180  |          1000 |             |        | {0: 900, 30: 50} | {0:0, 30:0}         |       10% |                             | 85, 0        | accept |
| Day 180  |           915 |             |        | {0: 900, 30: 50} | {0:85, 30:0}        |       10% |                             | 10, 0        | reject |
| Day 180  |           915 |             |        | {0: 900, 30: 50} | {0:85, 30:0}        |        5% |                             | 10, 0        | reject |
| Day 180  |           915 |             |        | {0: 900, 30: 50} | {0:85, 30:0}        |       10% |                             | 10, 0        | reject |
| Day 180  |           915 |             |        | {0: 900, 30: 50} | {0:85, 30:0}        |       10% |                             | 2, 0         | accept |
| Day 180  |           913 |             |        | {0: 900, 30: 50} | {0:87, 30:0}        |       10% |                             |              |        |
| Day 210  |               |             |        | {0: 900, 30: 50} | {0:87, 30:0}        |       10% |                             |       10, 30 | reject |
| Day 210  |               |             |        | {0: 900, 30: 50} | {0:87, 30:0}        |       20% |                             |       10, 30 | accept |
| Day 211  |               |             |        | {0: 900, 30: 50} | {0:87, 30:10}       |       20% |                             | 100, 0       | reject |
| Day 212  |               |             |        | {0: 900, 30: 50} | {0:87, 30:10}       |       20% |                         20% | 93, 0        | accept |
| Day 213  |               |             |        | {0: 900, 30: 50} | {0:180, 30:10}      |       20% |                         20% |              |        |
| Day 360  |               |             |        | {0: 900, 30: 50} | {0:180, 30:10}      |       20% |                         40% |              |        |
| Day 390  |               |             |        | {0: 900, 30: 50} | {0:180, 30:10}      |       15% |                         30% |              |        |

## Bridge contract requirements

* POND can be instantly converted into MPOND with 1MPOND yielded against 10^6 POND.
* To convert MPOND to POND, there is a delay of atleast W blocks.
* At any point, $min(100, liquidityRatio*floor[(time since request)/W])$ % of the total requested amount including all previous conversions for the request can be transferred to POND.
* If POND/MPOND are staked/delegated, then they can’t be transferred to the bridge.
* During wait period, MPOND can be used for governance and staking.
* User can partially/fully cancel conversion requests from MPOND to POND at any time, even after wait time is over as long as the conversion is not completed.
* Current conversion requests and their details should be efficiently retrievable.
* Bridge contract should be upgradable.
