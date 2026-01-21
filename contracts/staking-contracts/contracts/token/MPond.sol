// SPDX-License-Identifier: BSD-3-Clause

// Copyright 2020 Marlin contributors and Compound Labs, Inc.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./IArbToken.sol";

// do not use any of the OpenZeppelin ERC20 contracts or extensions
contract MPond is
    Initializable,  // initializer
    ContextUpgradeable,  // _msgSender, _msgData
    ERC165Upgradeable,  // supportsInterface
    AccessControlUpgradeable,  // RBAC
    AccessControlEnumerableUpgradeable,  // RBAC enumeration
    ERC1967UpgradeUpgradeable,  // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable,  // public upgrade
    IArbToken  // Arbitrum bridge support
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

//-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return interfaceId == type(IArbToken).interfaceId || super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) internal view override {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "MPond: must be admin to upgrade");
    }

//-------------------------------- Overrides end --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize() public initializer {
        // initialize parents
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();

        // set sender as admin
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        // mint supply to sender
        uint96 _amount = safe96(totalSupply, "Supply exceeds 2^96");
        balances[_msgSender()] = Balance(_amount, _amount, 0);
        emit Transfer(address(0), _msgSender(), totalSupply);
    }

//-------------------------------- Initializer end --------------------------------//

//-------------------------------- Whitelist start --------------------------------//

    uint256[50] private __gap2;

    /// @notice Role used for whitelist
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    function isWhitelistedTransfer(address _address1, address _address2)
        public
        view
        returns (bool)
    {
        if (
            hasRole(WHITELIST_ROLE, _address2) ||
            hasRole(WHITELIST_ROLE, _address1)
        ) {
            return true;
        }
        return false;
    }

//-------------------------------- Whitelist end --------------------------------//

//-------------------------------- ERC20 start --------------------------------//

    /// @notice EIP-20 token name for this token
    string public constant name = "Marlin MPond";

    /// @notice EIP-20 token symbol for this token
    string public constant symbol = "MPond";

    /// @notice EIP-20 token decimals for this token
    uint8 public constant decimals = 18;

    /// @notice Total number of tokens in circulation
    uint256 public constant totalSupply = 10000e18;  // 10k

    /// @notice Allowance amounts on behalf of others
    mapping(address => mapping(address => uint96)) internal allowances;

    /// @notice Optimize balances by storing multiple items in same slot
    struct Balance {
        uint96 undelegated;
        uint96 token;
        uint64 __unused;
    }

    /// @notice Official record of token balances for each account
    mapping(address => Balance) internal balances;

    uint256[48] private __gap3;

    /// @notice The standard EIP-20 approval event
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );

    /// @notice The standard EIP-20 transfer event
    event Transfer(address indexed from, address indexed to, uint256 amount);

    /**
     * @notice Get the number of tokens `spender` is approved to spend on behalf of `account`
     * @param account The address of the account holding the funds
     * @param spender The address of the account spending the funds
     * @return The number of tokens approved
     */
    function allowance(address account, address spender)
        external
        view
        returns (uint256)
    {
        return allowances[account][spender];
    }

    /**
     * @notice Approve `spender` to transfer up to `amount` from `src`
     * @dev This will overwrite the approval amount for `spender`
     *  and is subject to issues noted [here](https://eips.ethereum.org/EIPS/eip-20#approve)
     * @param spender The address of the account which may transfer tokens
     * @param rawAmount The number of tokens that are approved (2^256-1 means infinite)
     */
    function approve(address spender, uint256 rawAmount)
        external returns (bool)
    {
        uint96 amount;
        if (rawAmount == type(uint256).max) {
            amount = type(uint96).max;
        } else {
            amount = safe96(
                rawAmount,
                "MPond::approve: amount exceeds 96 bits"
            );
        }

        allowances[_msgSender()][spender] = amount;

        emit Approval(_msgSender(), spender, amount);

        return true;
    }

    function increaseAllowance(address spender, uint256 addedAmount)
        external
    {
        uint96 amount;
        if (addedAmount == type(uint256).max) {
            amount = type(uint96).max;
        } else {
            amount = safe96(
                addedAmount,
                "MPond::approve: addedAmount exceeds 96 bits"
            );
        }

        allowances[_msgSender()][spender] += amount;
        emit Approval(_msgSender(), spender, allowances[_msgSender()][spender]);
    }

    function decreaseAllowance(address spender, uint256 removedAmount)
        external
    {
        uint96 amount;
        if (removedAmount == type(uint256).max) {
            amount = type(uint96).max;
        } else {
            amount = safe96(
                removedAmount,
                "MPond::approve: removedAmount exceeds 96 bits"
            );
        }

        allowances[_msgSender()][spender] -= amount;
        emit Approval(_msgSender(), spender, allowances[_msgSender()][spender]);
    }

    /**
     * @notice Get the number of tokens held by the `account`
     * @param account The address of the account to get the balance of
     * @return The number of tokens held
     */
    function balanceOf(address account) external view returns (uint256) {
        return uint256(balances[account].token);
    }

    function undelegatedBalanceOf(address account) external view returns (uint256) {
        return uint256(balances[account].undelegated);
    }

    /**
     * @notice Transfer `amount` tokens from `_msgSender()` to `dst`
     * @param dst The address of the destination account
     * @param rawAmount The number of tokens to transfer
     */
    function transfer(address dst, uint256 rawAmount) external returns (bool) {
        require(
            isWhitelistedTransfer(_msgSender(), dst),
            "Atleast one of the address (src or dst) should be whitelisted or all transfers must be enabled via enableAllTransfers()"
        );
        uint96 amount = safe96(
            rawAmount,
            "MPond::transfer: amount exceeds 96 bits"
        );
        _transferTokens(_msgSender(), dst, amount);

        return true;
    }

    /**
     * @notice Transfer `amount` tokens from `src` to `dst`
     * @param src The address of the source account
     * @param dst The address of the destination account
     * @param rawAmount The number of tokens to transfer
     */
    function transferFrom(
        address src,
        address dst,
        uint256 rawAmount
    ) external returns (bool) {
        require(
            isWhitelistedTransfer(src, dst),
            "Atleast one of the address (src or dst) should be whitelisted or all transfers must be enabled via enableAllTransfers()"
        );
        address spender = _msgSender();
        uint96 spenderAllowance = allowances[src][spender];
        uint96 amount = safe96(
            rawAmount,
            "MPond::approve: amount exceeds 96 bits"
        );

        if (spender != src && spenderAllowance != type(uint96).max) {
            uint96 newAllowance = spenderAllowance - amount;
            allowances[src][spender] = newAllowance;

            emit Approval(src, spender, newAllowance);
        }

        _transferTokens(src, dst, amount);

        return true;
    }

    function _transferTokens(
        address src,
        address dst,
        uint96 amount
    ) internal {
        require(
            src != address(0),
            "MPond::_transferTokens: cannot transfer from the zero address"
        );
        require(
            dst != address(0),
            "MPond::_transferTokens: cannot transfer to the zero address"
        );

        Balance memory _srcBalance = balances[src];
        _srcBalance.undelegated -= amount;
        _srcBalance.token -= amount;
        balances[src] = _srcBalance;

        Balance memory _dstBalance = balances[dst];
        _dstBalance.undelegated += amount;
        _dstBalance.token += amount;
        balances[dst] = _dstBalance;

        emit Transfer(src, dst, amount);
    }

//-------------------------------- ERC20 end --------------------------------//

//-------------------------------- Delegation start --------------------------------//

    /// @notice A record of each accounts delegates and values except to 0x0 which is stored in balances
    mapping(address => mapping(address => uint96)) internal delegates;

    /// @notice A record of states for signing / validating signatures
    mapping(address => uint256) public nonces;

    uint256[48] private __gap4;

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );

    /// @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH = keccak256(
        "Delegation(address delegatee,uint256 nonce,uint256 expiry,uint96 amount)"
    );

    /// @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant UNDELEGATION_TYPEHASH = keccak256(
        "Undelegation(address delegatee,uint256 nonce,uint256 expiry,uint96 amount)"
    );

    /// @notice An event thats emitted when an account changes its delegate
    event DelegateChanged(
        address indexed delegator,
        address indexed fromDelegate,
        address indexed toDelegate
    );

    /// @notice An event thats emitted when a delegate account's vote balance changes
    event DelegateVotesChanged(
        address indexed delegate,
        uint256 previousBalance,
        uint256 newBalance
    );

    /**
     * @notice Get the number of tokens `delegator` has delegated to `delegatee`
     * @param delegator The address of the delegator
     * @param delegatee The address of the account which has been delegated to
     * @return The number of tokens delegated
     */
    function getDelegates(address delegator, address delegatee) external view returns (uint256){
        if(delegatee != address(0)) {
            return uint256(delegates[delegator][delegatee]);
        } else{
            return this.undelegatedBalanceOf(delegator);
        }
    }

    /**
     * @notice Delegate votes from `_msgSender()` to `delegatee`
     * @param delegatee The address to delegate votes to
     */
    function delegate(address delegatee, uint96 amount) public {
        return _delegate(_msgSender(), delegatee, amount);
    }

    function undelegate(address delegatee, uint96 amount) public {
        return _undelegate(_msgSender(), delegatee, amount);
    }

    /**
     * @notice Delegates votes from signatory to `delegatee`
     * @param delegatee The address to delegate votes to
     * @param nonce The contract state required to match the signature
     * @param expiry The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint96 amount
    ) public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                block.chainid,
                address(this)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry, amount)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        address signatory = ecrecover(digest, v, r, s);
        require(
            signatory != address(0),
            "MPond::delegateBySig: invalid signature"
        );
        require(
            nonce == nonces[signatory]++,
            "MPond::delegateBySig: invalid nonce"
        );
        require(block.timestamp <= expiry, "MPond::delegateBySig: signature expired");
        return _delegate(signatory, delegatee, amount);
    }

    function undelegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint96 amount
    ) public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                block.chainid,
                address(this)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(UNDELEGATION_TYPEHASH, delegatee, nonce, expiry, amount)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        address signatory = ecrecover(digest, v, r, s);
        require(
            signatory != address(0),
            "MPond::undelegateBySig: invalid signature"
        );
        require(
            nonce == nonces[signatory]++,
            "MPond::undelegateBySig: invalid nonce"
        );
        require(block.timestamp <= expiry, "MPond::undelegateBySig: signature expired");
        return _undelegate(signatory, delegatee, amount);
    }

    function _delegate(
        address delegator,
        address delegatee,
        uint96 amount
    ) internal {
        // zero address used as undelegated balance
        require(delegatee != address(0), "MPond: cannot delegate to 0");
        Balance memory _srcBalance = balances[delegator];
        _srcBalance.undelegated -= amount;
        balances[delegator] = _srcBalance;

        delegates[delegator][delegatee] += amount;

        emit DelegateChanged(delegator, address(0), delegatee);

        _moveDelegates(address(0), delegatee, amount);
    }

    function _undelegate(
        address delegator,
        address delegatee,
        uint96 amount
    ) internal {
        // zero address used as undelegated balance
        require(delegatee != address(0), "MPond: cannot undelegate from 0");
        delegates[delegator][delegatee] -= amount;

        Balance memory _srcBalance = balances[delegator];
        _srcBalance.undelegated += amount;
        balances[delegator] = _srcBalance;

        emit DelegateChanged(delegator, delegatee, address(0));
        _moveDelegates(delegatee, address(0), amount);
    }

//-------------------------------- Delegation end --------------------------------//


//-------------------------------- Checkpoints start --------------------------------//

    /// @notice A checkpoint for marking number of votes from a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint96 votes;
    }

    /// @notice A record of votes checkpoints for each account, by index
    mapping(address => mapping(uint32 => Checkpoint)) public checkpoints;

    /// @notice The number of checkpoints for each account
    mapping(address => uint32) public numCheckpoints;

    uint256[48] private __gap5;

    /**
     * @notice Gets the current votes balance for `account`
     * @param account The address to get votes balance
     * @return The number of current votes for `account`
     */
    function getCurrentVotes(address account) external view returns (uint96) {
        uint32 nCheckpoints = numCheckpoints[account];
        return
            nCheckpoints != 0
                ? checkpoints[account][nCheckpoints - 1].votes
                : 0;
    }

    /**
     * @notice Determine the prior number of votes for an account as of a block number
     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
     * @param account The address of the account to check
     * @param blockNumber The block number to get the vote balance at
     * @return The number of votes the account had as of the given block
     */
    function getPriorVotes(address account, uint256 blockNumber)
        public
        view
        returns (uint96)
    {
        require(
            blockNumber < block.number,
            "MPond::getPriorVotes: not yet determined"
        );

        uint32 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return 0;
        }

        // First check most recent balance
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        // Next check implicit zero balance
        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _moveDelegates(
        address srcRep,
        address dstRep,
        uint96 amount
    ) internal {
        if (srcRep != address(0)) {
            uint32 srcRepNum = numCheckpoints[srcRep];
            // srcRepNum should never be 0
            // if it is (due to bugs), tx will revert due to underflow
            // which matches previous behaviour inherited from compound
            uint96 srcRepOld = checkpoints[srcRep][srcRepNum - 1].votes;
            uint96 srcRepNew = srcRepOld - amount;
            _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
        }

        if (dstRep != address(0)) {
            uint32 dstRepNum = numCheckpoints[dstRep];
            uint96 dstRepOld = dstRepNum != 0
                ? checkpoints[dstRep][dstRepNum - 1].votes
                : 0;
            uint96 dstRepNew = dstRepOld + amount;
            _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
        }
    }

    function _writeCheckpoint(
        address delegatee,
        uint32 nCheckpoints,
        uint96 oldVotes,
        uint96 newVotes
    ) internal {
        uint32 blockNumber = safe32(
            block.number,
            "MPond::_writeCheckpoint: block number exceeds 32 bits"
        );

        if (
            nCheckpoints != 0 &&
            checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber
        ) {
            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
        } else {
            checkpoints[delegatee][nCheckpoints] = Checkpoint(
                blockNumber,
                newVotes
            );
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

//-------------------------------- Checkpoints end --------------------------------//


//-------------------------------- uint96 math start --------------------------------//

    uint256[50] private __gap6;

    function safe32(uint256 n, string memory errorMessage)
        internal
        pure
        returns (uint32)
    {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }

    function safe96(uint256 n, string memory errorMessage)
        internal
        pure
        returns (uint96)
    {
        require(n < 2**96, errorMessage);
        return uint96(n);
    }

//-------------------------------- uint96 math end --------------------------------//

//-------------------------------- Bridge start --------------------------------//

    // bridge mint/burn functions are implemented using transfers to/from the token contract itself
    // limits exposure to contract balance in case the bridge is compromised

    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");

    address public l1Address;
    uint256[49] private __gap7;

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()));
        _;
    }

    modifier onlyBridge() {
        require(hasRole(BRIDGE_ROLE, _msgSender()));
        _;
    }

    function setL1Address(address _l1Address) external onlyAdmin {
        l1Address = _l1Address;
    }

    function bridgeMint(address _account, uint256 _amount) external onlyBridge {
        _transferTokens(address(this), _account, safe96(_amount, "MPond: amount exceeds 96 bits"));
    }

    function bridgeBurn(address _account, uint256 _amount) external onlyBridge {
        _transferTokens(_account, address(this), safe96(_amount, "MPond: amount exceeds 96 bits"));
    }

    function withdraw(uint256 _amount) external onlyAdmin {
        _transferTokens(address(this), _msgSender(), safe96(_amount, "MPond: amount exceeds 96 bits"));
    }

//-------------------------------- Bridge end --------------------------------//
}

