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
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0);
    }

    function _authorizeUpgrade(address /*account*/ ) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap_1;

    function initialize(address _admin, IERC20 _token, bytes32[] memory _selectors, uint256[] memory _lockWaitTimes)
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
    
    function reinitialize() public onlyAdmin reinitializer(2) {
        // set the first 8 bytes of the job as a prefix with the chainId
        bytes8 chainIdBytes = bytes8(uint64(block.chainid));
        jobIndex = (bytes32(chainIdBytes) << 224);  
    }

    //-------------------------------- Initializer end --------------------------------//

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
        string metadata;
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

    uint256 public shutdownWindow;

    uint256[46] private __gap_3;

    event TokenUpdated(IERC20 indexed oldToken, IERC20 indexed newToken);
    event CreditTokenUpdated(IERC20 indexed oldCreditToken, IERC20 indexed newCreditToken);
    event ShutdownWindowUpdated(uint256 shutdownWindow);

    event JobOpened(bytes32 indexed jobId, string metadata, address indexed owner, address indexed provider);
    event JobSettled(bytes32 indexed jobId, address indexed token, uint256 amount, uint256 lastSettled);
    event JobClosed(bytes32 indexed jobId);
    event JobDeposited(bytes32 indexed jobId, address indexed token, address indexed from, uint256 amount);
    event JobWithdrawn(bytes32 indexed jobId, address indexed token, address indexed to, uint256 amount);
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

    function _updateToken(IERC20 _token) internal {
        token = _token;
        emit TokenUpdated(token, _token);
    }

    function updateToken(IERC20 _token) external onlyAdmin {
        _updateToken(_token);
    }

    function _updateShutdownWindow(uint256 _shutdownWindow) internal {
        shutdownWindow = _shutdownWindow;
        emit ShutdownWindowUpdated(_shutdownWindow);
    }

    function updateShutdownWindow(uint256 _shutdownWindow) external onlyAdmin {
        _updateShutdownWindow(_shutdownWindow);
    }

    function _updateCreditToken(IERC20 _creditToken) internal {
        creditToken = _creditToken;
        emit CreditTokenUpdated(creditToken, _creditToken);
    }

    function updateCreditToken(IERC20 _creditToken) external onlyAdmin {
        _updateCreditToken(_creditToken);
    }

    function emergencyWithdraw(address _token, address _to, uint256 _amount) external onlyAdmin {
        require(hasRole(EMERGENCY_WITHDRAW_ROLE, _msgSender()), "only to emergency withdraw role");
        IERC20(_token).safeTransfer(_to, _amount);
    }

    function _jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) internal {
        uint256 _jobIndex = uint256(jobIndex);
        jobIndex = bytes32(_jobIndex + 1);
        bytes32 jobId = bytes32(_jobIndex);

        // create job with initial balance 0
        jobs[jobId] = Job(_metadata, _msgSender(), _provider, 0, 0, block.timestamp);
        emit JobOpened(jobId, _metadata, _msgSender(), _provider);

        // deposit initial balance
        _deposit(jobId, _msgSender(), _balance);

        // set rate and pay shutdown delay cost upfront
        _jobReviseRate(jobId, _rate);
    }

    function _jobSettle(bytes32 _jobId) internal {
        require(block.timestamp > jobs[_jobId].lastSettled, "nothing to settle before lastSettled");

        uint256 usageDuration = block.timestamp - jobs[_jobId].lastSettled;
        uint256 amountUsed = _calcAmountUsed(jobs[_jobId].rate, usageDuration);
        uint256 settleAmount = _min(amountUsed, jobs[_jobId].balance);
        _settle(_jobId, settleAmount, block.timestamp);
    }

    function _jobClose(bytes32 _jobId) internal {
        uint256 lastSettled = jobs[_jobId].lastSettled;
        if (block.timestamp > lastSettled) {
            _jobSettle(_jobId);
        }

        // deduct shutdown delay cost
        _deductShutdownWindowCost(_jobId, jobs[_jobId].rate, lastSettled);

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
        _deposit(_jobId, _msgSender(), _amount);
    }

    function _jobWithdraw(bytes32 _jobId, uint256 _amount) internal {
        require(_amount > 0, "invalid amount");
        uint256 lastSettled = jobs[_jobId].lastSettled;

        if (block.timestamp > lastSettled) {
            _jobSettle(_jobId);
        }

        // calculate shutdown delay cost
        uint256 timeDelta = _calcTimeDelta(lastSettled);
        uint256 shutdownWindowCost = _calcAmountUsed(jobs[_jobId].rate, timeDelta);
        require(jobs[_jobId].balance > shutdownWindowCost, "balance below shutdown delay cost");

        // calculate max withdrawable amount
        uint256 maxWithdrawableAmount = jobs[_jobId].balance - shutdownWindowCost;
        require(_amount <= maxWithdrawableAmount, "amount exceeds max withdrawable amount");

        // withdraw
        _withdraw(_jobId, _msgSender(), _amount);
    }

    function _jobReviseRate(bytes32 _jobId, uint256 _newRate) internal {
        require(jobs[_jobId].rate != _newRate, "rate has not changed");

        uint256 lastSettled = jobs[_jobId].lastSettled;
        if (block.timestamp > lastSettled) {
            _jobSettle(_jobId);
        }

        // update rate and lastSettled
        uint256 oldRate = jobs[_jobId].rate;
        jobs[_jobId].rate = _newRate;
        emit JobRateRevised(_jobId, _newRate);

        // deduct shutdown delay cost
        // higher rate is used to calculate shutdown delay cost
        uint256 higherRate = _max(oldRate, _newRate);
        _deductShutdownWindowCost(_jobId, higherRate, lastSettled);
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
     *          the shutdownWindowCost, the provider is incentivized to shut down the job immediately after opening.
     *          Therefore, it should be noted that `(deposit amount) - shutdownWindowCost` is the actual amount to be
     *          used for running the job.
     * @dev     `shutdownWindowCost` is paid upfront.
     *          min(_balance, creditAllowance, creditBalance) amount of Credit tokens will be transferred from the caller to the job.
     * @param   _metadata  The metadata of the job.
     * @param   _provider  The provider of the job.
     * @param   _rate      The rate of the job.
     * @param   _balance   Amount of tokens to deposit into the job.
     */
    function jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) external {
        _jobOpen(_metadata, _provider, _rate, _balance);
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
        _jobSettle(_jobId);
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

    function _deductShutdownWindowCost(bytes32 _jobId, uint256 _rate, uint256 _lastSettled) internal {
        uint256 timeDelta = _calcTimeDelta(_lastSettled);
        uint256 shutdownWindowCost = _calcAmountUsed(_rate, timeDelta);
        require(jobs[_jobId].balance >= shutdownWindowCost, "balance below shutdown delay cost");
        _settle(_jobId, shutdownWindowCost, block.timestamp + shutdownWindow);
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

    function _calcTimeDelta(uint256 _lastSettled) internal view returns (uint256) {
        return block.timestamp < _lastSettled ? (block.timestamp + shutdownWindow) - _lastSettled : shutdownWindow;
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

    // TODO: gap?

    /**
     * @notice  Deposits the specified amount into the job balance.
     * @param   _jobId  The job to deposit to.
     * @param   _from  The address to deposit from.
     * @param   _amount  The amount to deposit.
     */
    function _deposit(bytes32 _jobId, address _from, uint256 _amount) internal {
        // total amount to deposit
        uint256 depositAmount = _amount;

        if (address(creditToken) != address(0)) {
            // amount to transfer from credit token
            uint256 creditBalanceTransferable =
                _min(creditToken.balanceOf(_from), creditToken.allowance(_from, address(this)));

            if (creditBalanceTransferable > 0) {
                uint256 creditTransferAmount;
                if (depositAmount > creditBalanceTransferable) {
                    depositAmount -= creditBalanceTransferable;
                    creditTransferAmount = creditBalanceTransferable;
                } else {
                    depositAmount = 0;
                    creditTransferAmount = depositAmount;
                }
                creditToken.safeTransferFrom(_from, address(this), creditTransferAmount);
                emit JobDeposited(_jobId, address(creditToken), _from, creditTransferAmount);
            }
        }

        if (depositAmount > 0) {
            token.safeTransferFrom(_from, address(this), depositAmount);
            emit JobDeposited(_jobId, address(token), _from, depositAmount);
        }

        jobs[_jobId].balance += _amount;
    }

    function _settle(bytes32 _jobId, uint256 _amount, uint256 _lastSettledUpdated) internal {
        address provider = jobs[_jobId].provider;
        uint256 settleAmount = _amount;

        jobs[_jobId].balance -= settleAmount;

        if (address(creditToken) != address(0)) {
            uint256 creditBalance = jobCreditBalance[_jobId];
            if (creditBalance > 0) {
                uint256 creditTransferAmount;
                if (settleAmount > creditBalance) {
                    jobCreditBalance[_jobId] = 0;
                    settleAmount -= creditBalance;
                    creditTransferAmount = creditBalance;
                } else {
                    jobCreditBalance[_jobId] -= settleAmount;
                    settleAmount = 0;
                    creditTransferAmount = settleAmount;
                }
                ICredit(address(creditToken)).redeemAndBurn(provider, creditTransferAmount);
                emit JobSettled(_jobId, address(creditToken), creditTransferAmount, _lastSettledUpdated);
            }
        }

        if (settleAmount > 0) {
            token.safeTransfer(provider, settleAmount);
            emit JobSettled(_jobId, address(token), settleAmount, _lastSettledUpdated);
        }

        jobs[_jobId].lastSettled = _lastSettledUpdated;
    }

    /**
     * @notice  Withdraws the specified amount from the job balance.
     * @dev     Use `_settle()` when settling a job and sending the amount settled to the job's provider.
     * @param   _jobId  The job to withdraw from.
     * @param   _to  The address to withdraw to.
     * @param   _amount  The amount to withdraw.
     */
    function _withdraw(bytes32 _jobId, address _to, uint256 _amount) internal {
        uint256 withdrawAmount = _amount;

        uint256 tokenBalance = jobs[_jobId].balance - jobCreditBalance[_jobId];
        jobs[_jobId].balance -= withdrawAmount;

        uint256 tokenAmountToTransfer;
        if(tokenBalance < withdrawAmount) {
            tokenAmountToTransfer = tokenBalance;
            withdrawAmount -= tokenBalance;
        } else {
            tokenAmountToTransfer = withdrawAmount;
            withdrawAmount = 0;
        }
        
        if(tokenAmountToTransfer > 0) {
            token.safeTransfer(_to, tokenAmountToTransfer);
            emit JobWithdrawn(_jobId, address(token), _to, tokenAmountToTransfer);
        }

        if(withdrawAmount > 0) {
            creditToken.safeTransfer(_to, withdrawAmount);
            jobCreditBalance[_jobId] -= withdrawAmount;
            emit JobWithdrawn(_jobId, address(creditToken), _to, withdrawAmount);
        }
    }
}

//--------------------------------- Payment Module end ---------------------------------//
