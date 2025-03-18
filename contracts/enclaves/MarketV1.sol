// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/* Libraries */
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/* Contracts */
import {LockUpgradeable} from "../lock/LockUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {
    UUPSUpgradeable,
    ERC1967UpgradeUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/* Interfaces */
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ICredit} from "./interfaces/ICredit.sol";

contract MarketV1 is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    ERC1967UpgradeUpgradeable, // delegate slots, proxy admin, private upgrade
    UUPSUpgradeable, // public upgrade
    LockUpgradeable // time locks
{
    using SafeERC20 for IERC20;

    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account)
        internal
        virtual
        override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable)
    {
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account)
        internal
        virtual
        override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable)
    {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "cannot remove all admins");
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap_1;

    function initialize(address _admin, address _token, bytes32[] memory _selectors, uint256[] memory _lockWaitTimes)
        public
        initializer
    {
        require(_selectors.length == _lockWaitTimes.length);

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1967Upgrade_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __Lock_init_unchained(_selectors, _lockWaitTimes);

        _setupRole(DEFAULT_ADMIN_ROLE, _admin);

        _updateToken(_token);
    }

    function reinitialize(uint256 _noticePeriod, address _creditToken) public onlyAdmin reinitializer(2) {
        // set the first 8 bytes of the job as a prefix with the chainId
        jobIndex = (bytes32(block.chainid) << 192) | jobIndex;

        _updateNoticePeriod(_noticePeriod);
        _updateCreditToken(_creditToken);
    }

    //--------------------------------- Initializer end --------------------------------//

    //-------------------------------- Providers start --------------------------------//

    struct Provider {
        string cp; // url of control plane
    }

    mapping(address => Provider) public providers;

    uint256[49] private __gap_2;

    event ProviderAdded(address indexed provider, string cp);
    event ProviderRemoved(address indexed provider);
    event ProviderUpdatedWithCp(address indexed provider, string newCp);

    function _providerAdd(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider].cp).length == 0, "already exists");
        require(bytes(_cp).length != 0, "invalid");

        providers[_provider] = Provider(_cp);

        emit ProviderAdded(_provider, _cp);
    }

    function _providerRemove(address _provider) internal {
        require(bytes(providers[_provider].cp).length != 0, "not found");

        delete providers[_provider];

        emit ProviderRemoved(_provider);
    }

    function _providerUpdateWithCp(address _provider, string memory _cp) internal {
        require(bytes(providers[_provider].cp).length != 0, "not found");
        require(bytes(_cp).length != 0, "invalid");

        providers[_provider].cp = _cp;

        emit ProviderUpdatedWithCp(_provider, _cp);
    }

    function providerAdd(string memory _cp) external {
        return _providerAdd(_msgSender(), _cp);
    }

    function providerRemove() external {
        return _providerRemove(_msgSender());
    }

    function providerUpdateWithCp(string memory _cp) external {
        return _providerUpdateWithCp(_msgSender(), _cp);
    }

    //-------------------------------- Providers end --------------------------------//

    //-------------------------------- Jobs start --------------------------------//

    bytes32 public constant RATE_LOCK_SELECTOR = keccak256("RATE_LOCK");
    bytes32 public constant EMERGENCY_WITHDRAW_ROLE = keccak256("EMERGENCY_WITHDRAW_ROLE"); // 0x66f144ecd65ad16d38ecdba8687842af4bc05fde66fe3d999569a3006349785f

    struct Job {
        string metadata; // TODO: fix to bytes
        address owner;
        address provider;
        uint256 rate;
        uint256 balance;
        uint256 lastSettled; // payment has been settled up to this timestamp
    }

    mapping(bytes32 => Job) public jobs;
    bytes32 public jobIndex;

    IERC20 public token;
    uint256 public constant EXTRA_DECIMALS = 12;

    uint256 public noticePeriod;

    uint256[46] private __gap_3;

    event TokenUpdated(address indexed oldToken, address indexed newToken);
    event CreditTokenUpdated(address indexed oldCreditToken, address indexed newCreditToken);
    event NoticePeriodUpdated(uint256 noticePeriod);

    event JobOpened(bytes32 indexed jobId, string metadata, address indexed owner, address indexed provider);
    event JobSettled(bytes32 indexed jobId, uint256 lastSettled);
    event JobClosed(bytes32 indexed jobId);
    event JobDeposited(bytes32 indexed jobId, address indexed token, address indexed from, uint256 amount);
    event JobWithdrawn(bytes32 indexed jobId, address indexed token, address indexed to, uint256 amount);
    event JobSettlementWithdrawn(
        bytes32 indexed jobId, address indexed token, address indexed provider, uint256 amount
    );
    event JobRateRevised(bytes32 indexed jobId, uint256 newRate);
    event JobMetadataUpdated(bytes32 indexed jobId, string metadata);

    modifier onlyExistingJob(bytes32 _jobId) {
        require(jobs[_jobId].owner != address(0), "job not found");
        _;
    }

    modifier onlyJobOwner(bytes32 _jobId) {
        require(jobs[_jobId].owner == _msgSender(), "only job owner");
        _;
    }

    function _updateToken(address _token) internal {
        address oldToken = address(token);
        token = IERC20(_token);
        emit TokenUpdated(oldToken, _token);
    }

    function _updateNoticePeriod(uint256 _noticePeriod) internal {
        noticePeriod = _noticePeriod;
        emit NoticePeriodUpdated(_noticePeriod);
    }

    function _updateCreditToken(address _creditToken) internal {
        address oldCreditToken = address(creditToken);
        creditToken = IERC20(_creditToken);
        emit CreditTokenUpdated(oldCreditToken, _creditToken);
    }

    function updateToken(address _token) external onlyAdmin {
        _updateToken(_token);
    }

    function updateNoticePeriod(uint256 _noticePeriod) external onlyAdmin {
        _updateNoticePeriod(_noticePeriod);
    }

    function updateCreditToken(address _creditToken) external onlyAdmin {
        _updateCreditToken(_creditToken);
    }

    function _emergencyWithdrawCredit(address _to, bytes32[] calldata _jobIds) internal {
        require(hasRole(EMERGENCY_WITHDRAW_ROLE, _to), "only to emergency withdraw role");

        uint256 settleTill = block.timestamp + noticePeriod;

        for (uint256 i = 0; i < _jobIds.length; i++) {
            bytes32 jobId = _jobIds[i];
            _jobSettle(jobId, jobs[jobId].rate, settleTill);
            uint256 creditBalance = jobCreditBalance[jobId];
            if (creditBalance > 0) {
                _withdraw(jobId, _to, creditBalance);
            }
        }
    }

    function emergencyWithdrawCredit(address _to, bytes32[] calldata _jobIds) external onlyAdmin {
        _emergencyWithdrawCredit(_to, _jobIds);
    }

    function _jobOpen(string calldata _metadata, address _owner, address _provider, uint256 _rate, uint256 _balance)
        internal
    {
        uint256 _jobIndex = uint256(jobIndex);
        jobIndex = bytes32(_jobIndex + 1);
        bytes32 jobId = bytes32(_jobIndex);

        // create job with initial balance 0
        jobs[jobId] = Job(_metadata, _owner, _provider, 0, 0, block.timestamp);
        emit JobOpened(jobId, _metadata, _owner, _provider);

        // deposit initial balance
        _deposit(jobId, _msgSender(), _balance);

        // set rate and pay shutdown delay cost upfront
        _jobReviseRate(jobId, _rate);
    }

    function _jobSettle(bytes32 _jobId, uint256 _rate, uint256 _settleTill) internal returns (bool isBalanceEnough) {
        uint256 lastSettled = jobs[_jobId].lastSettled;

        if (_settleTill == lastSettled) return true; // when JobOpen
        require(_settleTill > lastSettled, "cannot settle before lastSettled");

        uint256 usageDuration = _settleTill - lastSettled;
        uint256 amountUsed = _calcAmountUsed(_rate, usageDuration);
        uint256 settleAmount = _min(amountUsed, jobs[_jobId].balance);
        _settle(_jobId, settleAmount);
        jobs[_jobId].lastSettled = _settleTill;
        emit JobSettled(_jobId, _settleTill);

        isBalanceEnough = amountUsed <= settleAmount;
    }

    function _jobClose(bytes32 _jobId) internal {
        // deduct shutdown delay cost
        _jobSettle(_jobId, jobs[_jobId].rate, block.timestamp + noticePeriod);

        // refund leftover balance
        uint256 _balance = jobs[_jobId].balance;
        if (_balance > 0) {
            _withdraw(_jobId, _msgSender(), _balance);
        }

        delete jobs[_jobId];
        emit JobClosed(_jobId);
    }

    function _jobDeposit(bytes32 _jobId, uint256 _amount) internal {
        require(_amount > 0, "invalid amount");
        require(_jobSettle(_jobId, jobs[_jobId].rate, block.timestamp + noticePeriod), "insufficient funds to deposit");

        _deposit(_jobId, _msgSender(), _amount);
    }

    function _jobWithdraw(bytes32 _jobId, uint256 _amount) internal {
        require(_amount > 0, "invalid amount");
        require(_jobSettle(_jobId, jobs[_jobId].rate, block.timestamp + noticePeriod), "insufficient funds to withdraw");

        // withdraw
        _withdraw(_jobId, _msgSender(), _amount);
    }

    function _jobReviseRate(bytes32 _jobId, uint256 _newRate) internal {
        require(_newRate > 0, "invalid rate");
        require(jobs[_jobId].rate != _newRate, "rate has not changed");

        uint256 lastSettled = jobs[_jobId].lastSettled;
        if (block.timestamp > lastSettled) {
            require(
                _jobSettle(_jobId, jobs[_jobId].rate, block.timestamp),
                "insufficient funds to settle before revising rate"
            );
        }

        // update rate and lastSettled
        uint256 oldRate = jobs[_jobId].rate;
        jobs[_jobId].rate = _newRate;
        emit JobRateRevised(_jobId, _newRate);

        // deduct shutdown delay cost
        // higher rate is used to calculate shutdown delay cost
        uint256 higherRate = _max(oldRate, _newRate);
        require(_jobSettle(_jobId, higherRate, block.timestamp + noticePeriod), "insufficient funds to revise rate");
    }

    function _jobMetadataUpdate(bytes32 _jobId, string calldata _metadata) internal {
        string memory oldMetadata = jobs[_jobId].metadata;
        require(
            keccak256(abi.encodePacked(oldMetadata)) != keccak256(abi.encodePacked(_metadata)),
            "metadata has not changed"
        );
        jobs[_jobId].metadata = _metadata;
        emit JobMetadataUpdated(_jobId, _metadata);
    }

    /**
     * @notice  Opens a new job.
     *          To ensure the provider is paid for the shutdown window, if the deposit amount is exactly equal to
     *          the noticePeriodCost, the provider is incentivized to shut down the job immediately after opening.
     *          Therefore, it should be noted that `(deposit amount) - noticePeriodCost` is the actual amount to be
     *          used for running the job.
     * @dev     `noticePeriodCost` is paid upfront.
     *          min(_balance, creditAllowance, creditBalance) amount of Credit tokens will be transferred from the caller to the job.
     * @param   _metadata  The metadata of the job.
     * @param   _provider  The provider of the job.
     * @param   _rate      The rate of the job.
     * @param   _balance   Amount of tokens to deposit into the job.
     */
    function jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) external {
        _jobOpen(_metadata, _msgSender(), _provider, _rate, _balance);
    }

    /**
     * @notice  Settles the job and sends the amount settled to the job's provider.
     *          If the job has Credit balance, the credit balance will be deducted first.
     * @dev     Reverts if block.timestamp is before `lastSettled` of given jobId.
     *          If settled with Credit tokens the Credit tokens will be burned and redeemed to USDC when transfering
     *          to the job's provider.
     * @param   _jobId  The job to settle.
     */
    function jobSettle(bytes32 _jobId) external onlyExistingJob(_jobId) {
        _jobSettle(_jobId, jobs[_jobId].rate, block.timestamp);
    }

    /**
     * @notice  Closes the job and sends the remaining balance to the job's owner.
     *          The shutdown delay cost is deducted from the job's balance before refunding the remaining balance.
     * @dev     Settles the job before closing it.
     * @param   _jobId  The job to close.
     */
    function jobClose(bytes32 _jobId) external onlyExistingJob(_jobId) onlyJobOwner(_jobId) {
        _jobClose(_jobId);
    }

    /**
     * @notice  Deposits the specified amount into the job balance.
     *          min(_amount, creditAllowance, creditBalance) amount of Credit tokens will be transferred from the caller to the job.
     * @param   _jobId  The job to deposit to.
     * @param   _amount  The amount to deposit.
     */
    function jobDeposit(bytes32 _jobId, uint256 _amount) external onlyExistingJob(_jobId) {
        _jobDeposit(_jobId, _amount);
    }

    /**
     * @notice  Withdraws the specified amount from the job balance.
     *          If the amount required to be withdrawn is greater than the job's balance, the remaining balance will be
     *          transferred from the job to the caller as Credit tokens.
     * @dev     Reverts if block.timestamp is before `lastSettled` of given jobId.
     * @param   _jobId  The job to withdraw from.
     * @param   _amount  The amount to withdraw.
     */
    function jobWithdraw(bytes32 _jobId, uint256 _amount) external onlyExistingJob(_jobId) onlyJobOwner(_jobId) {
        _jobWithdraw(_jobId, _amount);
    }

    /**
     * @notice  Revises the rate of the job.
     *          Deducts the shutdown delay cost from the job's balance before updating the rate.
     * @dev     Reverts if the rate has not changed.
     * @param   _jobId  The job to revise the rate of.
     * @param   _newRate  The new rate of the job.
     */
    function jobReviseRate(bytes32 _jobId, uint256 _newRate) external onlyExistingJob(_jobId) onlyJobOwner(_jobId) {
        _jobReviseRate(_jobId, _newRate);
    }

    /**
     * @notice  Updates the metadata of the job.
     * @dev     Reverts if the metadata has not changed.
     * @param   _jobId  The job to update the metadata of.
     * @param   _metadata  The new metadata of the job.
     */
    function jobMetadataUpdate(bytes32 _jobId, string calldata _metadata)
        external
        onlyExistingJob(_jobId)
        onlyJobOwner(_jobId)
    {
        _jobMetadataUpdate(_jobId, _metadata);
    }

    function _calcAmountUsed(uint256 _rate, uint256 _usageDuration) internal pure returns (uint256) {
        return (_rate * _usageDuration + 10 ** EXTRA_DECIMALS - 1) / 10 ** EXTRA_DECIMALS;
    }

    function _max(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return _a > _b ? _a : _b;
    }

    function _min(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return _a < _b ? _a : _b;
    }

    //-------------------------------- Jobs end --------------------------------//

    //-------------------------------- Payment Module start --------------------------------//

    mapping(bytes32 => uint256) public jobCreditBalance;
    IERC20 public creditToken;

    uint256[50] private __gap_4;

    /**
     * @notice  Deposits the specified amount into the job balance.
     * @param   _jobId  The job to deposit to.
     * @param   _from  The address to deposit from.
     * @param   _amount  The amount to deposit.
     */
    function _deposit(bytes32 _jobId, address _from, uint256 _amount) internal {
        uint256 tokenAmount = _amount;
        uint256 creditAmount = 0;

        if (address(creditToken) != address(0)) {
            // amount to transfer from credit token
            uint256 creditBalance = _min(creditToken.balanceOf(_from), creditToken.allowance(_from, address(this)));

            if (creditBalance > 0) {
                (creditAmount, tokenAmount) = _calculateTokenSplit(_amount, creditBalance);
                creditToken.safeTransferFrom(_from, address(this), creditAmount);
                jobCreditBalance[_jobId] += creditAmount;
                emit JobDeposited(_jobId, address(creditToken), _from, creditAmount);
            }
        }

        if (tokenAmount > 0) {
            token.safeTransferFrom(_from, address(this), tokenAmount);
            emit JobDeposited(_jobId, address(token), _from, tokenAmount);
        }

        jobs[_jobId].balance += _amount;
    }

    function _settle(bytes32 _jobId, uint256 _amount) internal {
        address provider = jobs[_jobId].provider;

        jobs[_jobId].balance -= _amount;

        uint256 tokenAmount = _amount;
        uint256 creditAmount = 0;

        if (address(creditToken) != address(0)) {
            uint256 creditBalance = jobCreditBalance[_jobId];

            if (creditBalance > 0) {
                (creditAmount, tokenAmount) = _calculateTokenSplit(_amount, creditBalance);
                jobCreditBalance[_jobId] -= creditAmount;
                ICredit(address(creditToken)).redeemAndBurn(provider, creditAmount);
                emit JobSettlementWithdrawn(_jobId, address(creditToken), provider, creditAmount);
            }
        }

        if (tokenAmount > 0) {
            token.safeTransfer(provider, tokenAmount);
            emit JobSettlementWithdrawn(_jobId, address(token), provider, tokenAmount);
        }
    }

    /**
     * @notice  Calculates how much of each token type to use
     * @param   _totalAmount Total amount to process
     * @param   _creditBalance Available credit token amount
     * @return   creditAmount Amount to handle with credit tokens
     * @return  tokenAmount Amount to handle with payment tokens
     */
    function _calculateTokenSplit(uint256 _totalAmount, uint256 _creditBalance)
        internal
        pure
        returns (uint256 creditAmount, uint256 tokenAmount)
    {
        if (_totalAmount > _creditBalance) {
            creditAmount = _creditBalance;
            tokenAmount = _totalAmount - _creditBalance;
        } else {
            creditAmount = _totalAmount;
            tokenAmount = 0;
        }
        return (creditAmount, tokenAmount);
    }

    /**
     * @notice  Withdraws the specified amount from the job balance.
     * @param   _jobId  The job to withdraw from.
     * @param   _to  The address to withdraw to.
     * @param   _amount  The amount to withdraw.
     */
    function _withdraw(bytes32 _jobId, address _to, uint256 _amount) internal {
        uint256 jobBalance = jobs[_jobId].balance;
        require(jobBalance >= _amount, "withdrawal amount exceeds job balance");

        uint256 withdrawAmount = _amount;

        // shouldn't be possible
        uint256 jobCreditBalance_ = jobCreditBalance[_jobId];
        require(jobBalance >= jobCreditBalance_, "credit balance exceeds job balance");
        uint256 jobTokenBalance = jobBalance - jobCreditBalance_;
        jobs[_jobId].balance -= withdrawAmount;

        uint256 tokenAmountToTransfer;
        if (jobTokenBalance < withdrawAmount) {
            tokenAmountToTransfer = jobTokenBalance;
            withdrawAmount -= jobTokenBalance;
        } else {
            tokenAmountToTransfer = withdrawAmount;
            withdrawAmount = 0;
        }

        if (tokenAmountToTransfer > 0) {
            token.safeTransfer(_to, tokenAmountToTransfer);
            emit JobWithdrawn(_jobId, address(token), _to, tokenAmountToTransfer);
        }

        if (withdrawAmount > 0) {
            require(address(creditToken) != address(0), "credit token not set");
            jobCreditBalance[_jobId] -= withdrawAmount;
            creditToken.safeTransfer(_to, withdrawAmount);
            emit JobWithdrawn(_jobId, address(creditToken), _to, withdrawAmount);
        }
    }
}

//--------------------------------- Payment Module end ---------------------------------//
