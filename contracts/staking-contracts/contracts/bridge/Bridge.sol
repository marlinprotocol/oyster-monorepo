pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "../token/Pond.sol";
import "../token/MPond.sol";


// convertMultipleEpochs()
contract Bridge is
    Initializable, // initializer
    ContextUpgradeable,
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    UUPSUpgradeable // public upgrade
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor() initializer {}

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()));
        _;
    }
    modifier onlyGovernance() {
        require(hasRole(GOVERNANCE_ROLE, _msgSender()));
        _;
    }

//-------------------------------- Overrides start --------------------------------//

    function supportsInterface(bytes4 interfaceId) public view virtual override( ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool){
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable){
        super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable){
        super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "Cannot be adminless");
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyAdmin {}

//-------------------------------- Overrides ends --------------------------------//

//-------------------------------- Initializer start --------------------------------//

    uint256[50] private __gap1;

    function initialize(
        address _mpond,
        address _pond,
        address _stakingContract
    ) public initializer {
        mpond = MPond(_mpond);
        pond = Pond(_pond);
        stakingContract = _stakingContract;
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(GOVERNANCE_ROLE, _msgSender());

        startTime = block.timestamp;
        liquidityStartTime = block.timestamp;
        liquidityBp = 55;
        lockTimeEpochs = 1;
        liquidityEpochLength = 1 days;
    }

//-------------------------------- Initializer end --------------------------------//

    uint256 public constant pondPerMpond = 1000000;
    uint256 public constant epochLength = 1 days;
    uint256 public constant liquidityStartEpoch = 1;
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint256 public liquidityBp;
    uint256 public lockTimeEpochs;
    uint256 public liquidityEpochLength;

    MPond public mpond;
    Pond public pond;
    uint256 public startTime;
    uint256 public liquidityStartTime;

    struct Requests {
        uint256 amount;
        uint256 releaseEpoch;
    }

    event PlacedRequest(
        address indexed sender,
        uint256 requestCreateEpoch,
        uint256 unlockRequestEpoch
    );
    event MPondToPond(
        address indexed sender,
        uint256 indexed requestCreateEpoch,
        uint256 PondReceived
    );
    event PondToMPond(address indexed sender, uint256 MpondReceived);

    mapping(address => mapping(uint256 => Requests)) public requests; //address->epoch->Request(amount, lockTime)
    mapping(address => mapping(uint256 => uint256)) public claimedAmounts; //address->epoch->amount
    mapping(address => uint256) public totalAmountPlacedInRequests; //address -> amount

    address public stakingContract;


    function changeStakingContract(address _newAddr) external onlyGovernance {
        stakingContract = _newAddr;
    }

    function changeLiquidityBp(uint256 _newLbp) external onlyGovernance {
        liquidityBp = _newLbp;
    }

    // input should be number of days
    function changeLockTimeEpochs(uint256 _newLockTimeEpochs) external onlyGovernance {
        lockTimeEpochs = _newLockTimeEpochs;
    }

    // input should be number of days
    function changeLiquidityEpochLength(uint256 _newLiquidityEpochLength)
        external onlyGovernance
    {
        liquidityEpochLength = _newLiquidityEpochLength * 1 days;
    }

    function getCurrentEpoch() internal view returns (uint256) {
        return (block.timestamp - startTime) / (epochLength);
    }

    function getLiquidityEpoch(uint256 _startTime)
        public
        view
        returns (uint256)
    {
        if (block.timestamp < _startTime) {
            return 0;
        }
        return
            (block.timestamp - _startTime) /
            (liquidityEpochLength) +
            liquidityStartEpoch;
    }

    function effectiveLiquidity(uint256 _startTime)
        public
        view
        returns (uint256)
    {
        uint256 effective = getLiquidityEpoch(_startTime) * liquidityBp;
        if (effective > 10000) {
            return 10000;
        }
        return effective;
    }

    function getConvertableAmount(address _address, uint256 _epoch)
        public
        view
        returns (uint256)
    {
        uint256 _reqAmount = requests[_address][_epoch].amount;
        uint256 _reqReleaseTime = (requests[_address][_epoch].releaseEpoch *
            epochLength) + liquidityStartTime;
        uint256 _claimedAmount = claimedAmounts[_address][_epoch];
        if (
            _claimedAmount >=
            (_reqAmount * effectiveLiquidity(_reqReleaseTime)) / (10000)
        ) {
            return 0;
        }
        return
            ((_reqAmount * effectiveLiquidity(_reqReleaseTime)) / (10000)) -
            _claimedAmount;
    }

    function convert(uint256 _epoch, uint256 _amount) public returns (uint256) {
        require(_amount != 0, "Should be non zero amount");
        uint256 _claimedAmount = claimedAmounts[_msgSender()][_epoch];
        uint256 totalUnlockableAmount = _claimedAmount + _amount;
        Requests memory _req = requests[_msgSender()][_epoch];
        uint256 _reqReleaseTime = (_req.releaseEpoch * epochLength) + liquidityStartTime;

        // replace div with actual divide
        require(
            totalUnlockableAmount <=
                (_req.amount * effectiveLiquidity(_reqReleaseTime)) / (10000),
            "total unlock amount should be less than or equal to requests_amount*effective_liquidity."
        );
        require(
            getCurrentEpoch() >= _req.releaseEpoch,
            "Funds can only be released after requests exceed locktime"
        );
        claimedAmounts[_msgSender()][_epoch] = totalUnlockableAmount;

        mpond.transferFrom(_msgSender(), address(this), _amount);
        // pond.tranfer(_msgSender(), _amount.mul(pondPerMpond));
        SafeERC20Upgradeable.safeTransfer(
            pond,
            _msgSender(),
            _amount * pondPerMpond
        );
        uint256 amountLockedInRequests = totalAmountPlacedInRequests[
            _msgSender()
        ];
        totalAmountPlacedInRequests[_msgSender()] =
            amountLockedInRequests -
            _amount;
        emit MPondToPond(_msgSender(), _epoch, _amount * pondPerMpond);
        return _amount * pondPerMpond;
    }

    // function placeRequest(uint256 amount) external returns (uint256, uint256) {
    //     uint256 epoch = getCurrentEpoch();
    //     uint256 amountInRequests = totalAmountPlacedInRequests[_msgSender()];
    //     uint256 amountOnWhichRequestCanBePlaced = mpond.balanceOf(_msgSender()) +
    //         mpond.getDelegates(stakingContract, _msgSender()) -
    //         amountInRequests;
    //     require(
    //         amount != 0 && amount <= amountOnWhichRequestCanBePlaced,
    //         "Request should be placed with amount greater than 0 and less than remainingAmount"
    //     );
    //     // require(
    //     //     amount != 0 && amount <= mpond.balanceOf(_msgSender()),
    //     //     "Request should be placed with amount greater than 0 and less than the balance of the user"
    //     // );
    //     require(
    //         requests[_msgSender()][epoch].amount == 0,
    //         "Only one request per epoch is acceptable"
    //     );
    //     Requests memory _req = Requests(amount, epoch + lockTimeEpochs);
    //     requests[_msgSender()][epoch] = _req;
    //     totalAmountPlacedInRequests[_msgSender()] = amountInRequests + amount;
    //     emit PlacedRequest(_msgSender(), epoch, _req.releaseEpoch);
    //     return (epoch, _req.releaseEpoch);
    // }

    function addLiquidity(uint256 _mpond, uint256 _pond)
        external
        onlyAdmin
        returns (bool)
    {
        mpond.transferFrom(_msgSender(), address(this), _mpond);
        // pond.transferFrom(_msgSender(), address(this), _pond);
        SafeERC20Upgradeable.safeTransferFrom(
            pond,
            _msgSender(),
            address(this),
            _pond
        );
        return true;
    }

    function removeLiquidity(
        uint256 _mpond,
        uint256 _pond,
        address _withdrawAddress
    ) external onlyAdmin returns (bool) {
        mpond.transfer(_withdrawAddress, _mpond);
        // pond.transfer(_withdrawAddress, _pond);
        SafeERC20Upgradeable.safeTransfer(pond, _withdrawAddress, _pond);
        return true;
    }

    function getLiquidity() public view returns (uint256, uint256) {
        return (pond.balanceOf(address(this)), mpond.balanceOf(address(this)));
    }

    function getMpond(uint256 _mpond) public returns (uint256) {
        uint256 pondToDeduct = _mpond * pondPerMpond;
        // pond.transferFrom(_msgSender(), address(this), pondToDeduct);
        SafeERC20Upgradeable.safeTransferFrom(
            pond,
            _msgSender(),
            address(this),
            pondToDeduct
        );
        mpond.transfer(_msgSender(), _mpond);
        emit PondToMPond(_msgSender(), _mpond);
        return pondToDeduct;
    }
}
