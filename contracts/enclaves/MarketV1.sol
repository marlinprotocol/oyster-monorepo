// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

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
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {LockUpgradeable} from "../lock/LockUpgradeable.sol";

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

    function providerAdd(string memory _cp) external {
        require(bytes(providers[_msgSender()].cp).length == 0, "already exists");
        require(bytes(_cp).length != 0, "invalid");

        providers[_msgSender()] = Provider(_cp);

        emit ProviderAdded(_msgSender(), _cp);
    }

    function providerRemove() external {
        require(bytes(providers[_msgSender()].cp).length != 0, "not found");

        delete providers[_msgSender()];

        emit ProviderRemoved(_msgSender());
    }

    function providerUpdateWithCp(string memory _cp) external {
        require(bytes(providers[_msgSender()].cp).length != 0, "not found");
        require(bytes(_cp).length != 0, "invalid");

        providers[_msgSender()].cp = _cp;

        emit ProviderUpdatedWithCp(_msgSender(), _cp);
    }

    //-------------------------------- Providers end --------------------------------//

    //-------------------------------- Jobs start --------------------------------//

    bytes32 public constant RATE_LOCK_SELECTOR = keccak256("RATE_LOCK");

    struct Job {
        string metadata;
        address owner;
        address provider;
        uint256 rate;
        uint256 balance;
        uint256 paymentSettledTimestamp; // payment has been settled up to this timestamp
    }

    mapping(bytes32 => Job) public jobs;
    uint256 public jobIndex;

    IERC20 public token;
    uint256 public constant EXTRA_DECIMALS = 12;

    uint256 public shutdownWindow;

    uint256[46] private __gap_3;

    event TokenUpdated(IERC20 indexed oldToken, IERC20 indexed newToken);
    event CreditTokenUpdated(IERC20 indexed oldCreditToken, IERC20 indexed newCreditToken);
    event ShutdownWindowUpdated(uint256 shutdownWindow);

    event JobOpened(
        bytes32 indexed job,
        string metadata,
        address indexed owner,
        address indexed provider,
        uint256 rate,
        uint256 balance,
        uint256 paymentSettledTimestamp
    );
    event JobSettled(bytes32 indexed job, uint256 amount);
    event JobClosed(bytes32 indexed job);
    event JobDeposited(bytes32 indexed job, address indexed from, uint256 amount);
    event JobWithdrew(bytes32 indexed job, address indexed to, uint256 amount);
    event JobRateRevised(bytes32 indexed job, uint256 newRate, uint256 paymentSettledTimestamp);
    event JobMetadataUpdated(bytes32 indexed job, string metadata);

    modifier onlyExistingJob(bytes32 _job) {
        require(jobs[_job].owner != address(0), "job not found");
        _;
    }

    modifier onlyJobOwner(bytes32 _job) {
        require(jobs[_job].owner == _msgSender(), "only job owner");
        _;
    }

    /**
     * @notice  Opens a new job.
     *          To ensure the provider is paid for the shutdown window, if the deposit amount is exactly equal to
     *          the shutdownWindowCost, the provider is incentivized to shut down the job immediately after opening.
     *          Therefore, it should be noted that `(deposit amount) - shutdownWindowCost` is the actual amount to be
     *          used for running the job.
     * @dev     `shutdownWindowCost` is paid upfront.
     * @param   _metadata  The metadata of the job.
     * @param   _provider  The provider of the job.
     * @param   _rate      The rate of the job.
     * @param   _balance   The balance of the job.
     */
    function jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) external {
        uint256 shutdownWindowCost = _calcAmountUsed(_rate, shutdownWindow);
        require(_balance > shutdownWindowCost, "not enough balance");

        uint256 _jobIndex = jobIndex;
        jobIndex = _jobIndex + 1;
        bytes32 job = bytes32(_jobIndex);

        // create job with initial balance 0
        jobs[job] =
            Job(_metadata, _msgSender(), _provider, _rate, 0, block.timestamp + shutdownWindow);

        // deposit initial balance
        _deposit(job, _msgSender(), _balance);

        // shutdown delay is paid upfront
        _settle(job, shutdownWindowCost);
        
        emit JobOpened(job, _metadata, _msgSender(), _provider, _rate, jobs[job].balance, block.timestamp + shutdownWindow);
    }

    function jobSettle(bytes32 _job) external onlyExistingJob(_job) {
        require(jobs[_job].owner != address(0), "job not found");
        require(
            block.timestamp > jobs[_job].paymentSettledTimestamp, "nothing to settle before paymentSettledTimestamp"
        );
        _jobSettle(_job);
    }

    function jobClose(bytes32 _job) external onlyExistingJob(_job) onlyJobOwner(_job) {
        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;
        if (block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // deduct shutdown delay cost
        _deductShutdownWindowCost(_job, jobs[_job].rate, paymentSettledTimestamp);

        // refund leftover balance
        uint256 _balance = jobs[_job].balance;
        if (_balance > 0) {
            _withdraw(_job, _msgSender(), _balance);
        }

        delete jobs[_job];
        emit JobClosed(_job);
    }

    function jobDeposit(bytes32 _job, uint256 _amount) external onlyExistingJob(_job) {
        require(_amount > 0, "invalid amount");
        _deposit(_job, _msgSender(), _amount);
        emit JobDeposited(_job, _msgSender(), _amount);
    }

    function jobWithdraw(bytes32 _job, uint256 _amount) external onlyExistingJob(_job) onlyJobOwner(_job) {
        require(_amount > 0, "invalid amount");
        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;

        if (block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // calculate shutdown delay cost
        uint256 timeDelta = _calcTimeDelta(paymentSettledTimestamp);
        uint256 shutdownWindowCost = _calcAmountUsed(jobs[_job].rate, timeDelta);
        require(jobs[_job].balance > shutdownWindowCost, "balance below shutdown delay cost");

        // calculate max withdrawable amount
        uint256 maxWithdrawableAmount = jobs[_job].balance - shutdownWindowCost;
        require(_amount <= maxWithdrawableAmount, "amount exceeds max withdrawable amount");

        // withdraw
        _withdraw(_job, _msgSender(), _amount);

        emit JobWithdrew(_job, _msgSender(), _amount);
    }

    function jobReviseRate(bytes32 _job, uint256 _newRate) external onlyExistingJob(_job) onlyJobOwner(_job) {
        require(jobs[_job].rate != _newRate, "rate has not changed");

        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;
        if (block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // deduct shutdown delay cost
        uint256 rate = _max(jobs[_job].rate, _newRate);
        _deductShutdownWindowCost(_job, rate, paymentSettledTimestamp);

        // update rate and paymentSettledTimestamp
        jobs[_job].rate = _newRate;
        uint256 paymentSettledTimestampUpdated = block.timestamp + shutdownWindow;
        jobs[_job].paymentSettledTimestamp = paymentSettledTimestampUpdated;
        emit JobRateRevised(_job, _newRate, paymentSettledTimestampUpdated);
    }

    function jobMetadataUpdate(bytes32 _job, string calldata _metadata)
        external
        onlyExistingJob(_job)
        onlyJobOwner(_job)
    {
        string memory oldMetadata = jobs[_job].metadata;
        require(
            keccak256(abi.encodePacked(oldMetadata)) != keccak256(abi.encodePacked(_metadata)),
            "metadata has not changed"
        );
        jobs[_job].metadata = _metadata;
        emit JobMetadataUpdated(_job, _metadata);
    }

    /**
     * @dev     block.timestamp > paymentSettleds should be checked before calling this function
     */
    function _jobSettle(bytes32 _job) internal {
        uint256 usageDuration = block.timestamp - jobs[_job].paymentSettledTimestamp;
        uint256 amountUsed = _calcAmountUsed(jobs[_job].rate, usageDuration);
        uint256 settleAmount = _min(amountUsed, jobs[_job].balance);
        _settle(_job, settleAmount);

        jobs[_job].paymentSettledTimestamp = block.timestamp;

        emit JobSettled(_job, settleAmount);
    }

    function _deductShutdownWindowCost(bytes32 _job, uint256 _rate, uint256 _paymentSettled) internal {
        uint256 timeDelta = _calcTimeDelta(_paymentSettled);
        uint256 shutdownWindowCost = _calcAmountUsed(_rate, timeDelta);
        require(jobs[_job].balance >= shutdownWindowCost, "balance below shutdown delay cost");
        _settle(_job, shutdownWindowCost);
    }


    function _calcTimeDelta(uint256 _paymentSettledTimestamp) internal view returns (uint256) {
        return block.timestamp < _paymentSettledTimestamp
            ? (block.timestamp + shutdownWindow) - _paymentSettledTimestamp
            : shutdownWindow;
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
     * @param   _job  The job to deposit to.
     * @param   _from  The address to deposit from.
     * @param   _amount  The amount to deposit.
     */
    function _deposit(bytes32 _job, address _from, uint256 _amount) internal {
        // total amount to deposit
        uint256 depositAmount = _amount;

        // amount to transfer from credit token
        uint256 creditBalanceTransferable = _min(
            creditToken.balanceOf(_from), 
            creditToken.allowance(_from, address(this))
        );

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
        }

        if (depositAmount > 0) {
            token.safeTransferFrom(_from, address(this), depositAmount);
        }
        
        jobs[_job].balance += _amount;
    }

    function _settle(bytes32 _job, uint256 _amount) internal {
        address provider = jobs[_job].provider;
        uint256 settleAmount = _amount;
        uint256 creditBalance = jobCreditBalance[_job];

        jobs[_job].balance -= settleAmount;

        if (creditBalance > 0) {
            uint256 creditTransferAmount;
            if (settleAmount > creditBalance) {
                jobCreditBalance[_job] = 0;
                settleAmount -= creditBalance;
                creditTransferAmount = creditBalance;
            } else {
                jobCreditBalance[_job] -= settleAmount;
                settleAmount = 0;
                creditTransferAmount = settleAmount;
            }
            // TODO: redeem from Credit contract
            creditToken.safeTransfer(provider, creditTransferAmount);
        }

        if (settleAmount > 0) {
            token.safeTransfer(provider, settleAmount);
        }
    }

    /**
     * @notice  Withdraws the specified amount from the job balance.
     * @dev     Use `_settle()` when settling a job and sending the amount settled to the job's provider.
     * @param   _job  The job to withdraw from.
     * @param   _to  The address to withdraw to.
     * @param   _amount  The amount to withdraw.
     */
    function _withdraw(bytes32 _job, address _to, uint256 _amount) internal {
        uint256 withdrawAmount = _amount;
        uint256 creditBalance = jobCreditBalance[_job];

        if (creditBalance > 0) {    
            uint256 creditTransferAmount;
            if (withdrawAmount > creditBalance) {
                jobCreditBalance[_job] = 0;
                withdrawAmount -= creditBalance;
                creditTransferAmount = creditBalance;
            } else {
                jobCreditBalance[_job] -= withdrawAmount;
                withdrawAmount = 0; 
                creditTransferAmount = withdrawAmount;
            }
            creditToken.safeTransfer(_to, creditTransferAmount);
        }

        if (withdrawAmount > 0) {
            token.safeTransfer(_to, withdrawAmount);
        }
    }

    //--------------------------------- Payment Module end ---------------------------------//

    //----------------------------------- Admin start -----------------------------------//

    function updateToken(IERC20 _token) external onlyAdmin {
        require(address(_token) != address(0), "invalid token address");
        _updateToken(_token);
    }

    function _updateToken(IERC20 _token) internal {
        token = _token;
        emit TokenUpdated(token, _token);
    }

    function updateShutdownWindow(uint256 _shutdownWindow) external onlyAdmin {
        require(_shutdownWindow > 0, "invalid shutdown delay");
        _updateShutdownWindow(_shutdownWindow);
    }

    function _updateShutdownWindow(uint256 _shutdownWindow) internal {
        shutdownWindow = _shutdownWindow;
        emit ShutdownWindowUpdated(_shutdownWindow);
    }

    function updateCreditToken(IERC20 _creditToken) external onlyAdmin {
        require(address(_creditToken) != address(0), "invalid credit token address");
        _updateCreditToken(_creditToken);
    }

    function _updateCreditToken(IERC20 _creditToken) internal {
        creditToken = _creditToken;
        emit CreditTokenUpdated(creditToken, _creditToken);
    }

    //----------------------------------- Admin start -----------------------------------//
}
