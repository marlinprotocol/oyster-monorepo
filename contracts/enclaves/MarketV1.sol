// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../lock/LockUpgradeable.sol";

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
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer { }

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._grantRole(role, account);
    }

    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) {
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0);
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap_1;

    function initialize(address _admin, IERC20 _token, bytes32[] memory _selectors, uint256[] memory _lockWaitTimes) public initializer {
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

    uint256 public shutdownDelay;

    uint256[46] private __gap_3;

    event TokenUpdated(IERC20 indexed oldToken, IERC20 indexed newToken);
    event ShutdownDelayUpdated(uint256 shutdownDelay);

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

    function _updateToken(IERC20 _token) internal {
        emit TokenUpdated(token, _token);
        token = _token;
    }

    function updateToken(IERC20 _token) external onlyAdmin {
        _updateToken(_token);
    }

    function _updateShutdownDelay(uint256 _shutdownDelay) internal {
        shutdownDelay = _shutdownDelay;
        emit ShutdownDelayUpdated(_shutdownDelay);
    }

    function updateShutdownDelay(uint256 _shutdownDelay) external onlyAdmin {
        require(_shutdownDelay > 0, "invalid shutdown delay");
        _updateShutdownDelay(_shutdownDelay);
    }

    function _deposit(address _from, uint256 _amount) internal {
        token.transferFrom(_from, address(this), _amount);
    }

    function _withdraw(address _to, uint256 _amount) internal {
        token.transfer(_to, _amount);
    }

    function _jobOpen(string memory _metadata, address _owner, address _provider, uint256 _rate, uint256 _balance) internal {
        uint256 shutdownDelayCost = _calcAmountUsed(_rate, shutdownDelay);        
        require(_balance > shutdownDelayCost, "not enough balance"); // TODO: maybe force shutdownDelayCost + 1min?

        _deposit(_owner, _balance);
        
        _balance -= shutdownDelayCost;
        _withdraw(_provider, shutdownDelayCost); // shutdown delay is paid upfront

        uint256 _jobIndex = jobIndex;
        jobIndex = _jobIndex + 1;
        bytes32 _job = bytes32(_jobIndex);
        jobs[_job] = Job(_metadata, _owner, _provider, _rate, _balance, block.timestamp + shutdownDelay);

        emit JobOpened(_job, _metadata, _owner, _provider, _rate, _balance, block.timestamp + shutdownDelay);
    }

    /**
     * @dev     block.timestamp > paymentSettleds should be checked before calling this function
     */
    function _jobSettle(bytes32 _job) internal {
        address _provider = jobs[_job].provider;
        uint256 _rate = jobs[_job].rate;
        uint256 _balance = jobs[_job].balance;
        uint256 _paymentSettled = jobs[_job].paymentSettledTimestamp;

        uint256 _usageDuration = block.timestamp - _paymentSettled;
        uint256 _amount = _calcAmountUsed(_rate, _usageDuration);
        if (_amount > _balance) {
            _amount = _balance; // withdraw all if balance is insufficient
            _balance = 0;
            // TODO: delete job if _amount >= balance?
        } else {
            _balance -= _amount;
        }
        _withdraw(_provider, _amount);

        jobs[_job].balance = _balance;  
        jobs[_job].paymentSettledTimestamp = block.timestamp;

        emit JobSettled(_job, _amount);
    }

    function _jobClose(bytes32 _job) internal {
        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;
        if(block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // deduct shutdown delay cost
        _deductShutdownDelayCost(_job, jobs[_job].rate, paymentSettledTimestamp);

        // refund leftover balance
        uint256 _balance = jobs[_job].balance;
        if (_balance > 0) {
            address _owner = jobs[_job].owner;
            jobs[_job].balance = 0;
            _withdraw(_owner, _balance);
        }

        delete jobs[_job];
        emit JobClosed(_job);
    }

    function _jobDeposit(bytes32 _job, address _from, uint256 _amount) internal {
        _deposit(_from, _amount);
        jobs[_job].balance += _amount;

        emit JobDeposited(_job, _from, _amount);
    }

    function _jobWithdraw(bytes32 _job, address _to, uint256 _amount) internal {
        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;
        if(block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // calculate shutdown delay cost
        uint256 timeDelta = _calcTimeDelta(paymentSettledTimestamp);
        uint256 shutdownDelayCost = _calcAmountUsed(jobs[_job].rate, timeDelta);
        require(jobs[_job].balance > shutdownDelayCost, "balance below shutdown delay cost");

        // calculate max withdrawable amount
        uint256 maxWithdrawableAmount = jobs[_job].balance - shutdownDelayCost;
        require(_amount <= maxWithdrawableAmount, "amount exceeds max withdrawable amount");
        
        // withdraw
        jobs[_job].balance -= _amount;
        _withdraw(_to, _amount);

        emit JobWithdrew(_job, _to, _amount);
    }

    function _jobReviseRate(bytes32 _job, uint256 _newRate) internal {
        uint256 paymentSettledTimestamp = jobs[_job].paymentSettledTimestamp;
        if (block.timestamp > paymentSettledTimestamp) {
            _jobSettle(_job);
        }

        // deduct shutdown delay cost
        uint256 rate = _max(jobs[_job].rate, _newRate);
        _deductShutdownDelayCost(_job, rate, paymentSettledTimestamp);

        // update rate and paymentSettledTimestamp
        jobs[_job].rate = _newRate;
        uint256 paymentSettledTimestampUpdated = block.timestamp + shutdownDelay;
        jobs[_job].paymentSettledTimestamp = paymentSettledTimestampUpdated;
        emit JobRateRevised(_job, _newRate, paymentSettledTimestampUpdated);
    }

    function _jobMetadataUpdate(bytes32 _job, string memory _metadata) internal {
        jobs[_job].metadata = _metadata;
        emit JobMetadataUpdated(_job, _metadata);
    }

    function _calcTimeDelta(uint256 _paymentSettledTimestamp) internal view returns (uint256) {
        return block.timestamp < _paymentSettledTimestamp ? (block.timestamp + shutdownDelay) - _paymentSettledTimestamp : shutdownDelay;
    }

    function _calcAmountUsed(uint256 _rate, uint256 _usageDuration) internal pure returns (uint256) {
        return (_rate * _usageDuration + 10 ** EXTRA_DECIMALS - 1) / 10 ** EXTRA_DECIMALS;
    }

    function _deductShutdownDelayCost(bytes32 _job, uint256 _rate, uint256 _paymentSettled) internal {
        uint256 timeDelta = _calcTimeDelta(_paymentSettled);
        uint256 shutdownDelayCost = _calcAmountUsed(_rate, timeDelta);
        require(jobs[_job].balance >= shutdownDelayCost, "balance below shutdown delay cost");
    
        jobs[_job].balance -= shutdownDelayCost;
        _withdraw(jobs[_job].provider, shutdownDelayCost);
    }

    function _max(uint256 _a, uint256 _b) internal pure returns (uint256) {
        return _a > _b ? _a : _b;
    }

    function jobOpen(string calldata _metadata, address _provider, uint256 _rate, uint256 _balance) external {
        return _jobOpen(_metadata, _msgSender(), _provider, _rate, _balance);
    }

    function jobSettle(bytes32 _job) external onlyExistingJob(_job) {
        require(jobs[_job].owner != address(0), "job not found");
        require(block.timestamp > jobs[_job].paymentSettledTimestamp, "nothing to settle before paymentSettledTimestamp");
        _jobSettle(_job);
    }

    function jobClose(bytes32 _job) external onlyExistingJob(_job) onlyJobOwner(_job) {
        _jobClose(_job);
    }

    function jobDeposit(bytes32 _job, uint256 _amount) external onlyExistingJob(_job) {
        require(_amount > 0, "invalid amount");
        _jobDeposit(_job, _msgSender(), _amount);
    }

    function jobWithdraw(bytes32 _job, uint256 _amount) external onlyExistingJob(_job) onlyJobOwner(_job) {
        require(_amount > 0, "invalid amount");
        _jobWithdraw(_job, _msgSender(), _amount);
    }

    function jobReviseRate(bytes32 _job, uint256 _newRate) external onlyExistingJob(_job) onlyJobOwner(_job) {
        require(jobs[_job].rate != _newRate, "no rate change");
        _jobReviseRate(_job, _newRate);
    }

    function jobMetadataUpdate(bytes32 _job, string calldata _metadata) external onlyJobOwner(_job) {
        _jobMetadataUpdate(_job, _metadata);
    }
    
    //-------------------------------- Jobs end --------------------------------//
}
