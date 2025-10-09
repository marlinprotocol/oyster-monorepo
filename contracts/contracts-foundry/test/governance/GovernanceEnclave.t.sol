// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {GovernanceEnclave} from "../../src/governance/GovernanceEnclave.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockEnclave} from "./mocks/MockEnclave.t.sol";

contract GovernanceEnclaveTest is Test {
    GovernanceEnclave public governanceEnclave;
    MockEnclave public mockEnclave;

    // Test addresses
    address public admin;
    address public configSetter;
    address public user;

    // Test configuration
    string public kmsPath;
    bytes public kmsRootServerPubKey;
    bytes public pcr0;
    bytes public pcr1;
    bytes public pcr2;
    uint256 public maxRPCUrlsPerChain;

    // Cached values for verification tests
    bytes public enclavePubKey;
    uint256 public enclavePrivKey;

    // Constants for testing
    uint256 constant TEST_CHAIN_ID = 1;
    string constant TEST_RPC_URL = "https://rpc.example.com";

    function setUp() public {
        // Initialize test addresses
        admin = makeAddr("admin");
        configSetter = makeAddr("configSetter");
        user = makeAddr("user");

        // Initialize test data
        kmsPath = "governance_test";
        kmsRootServerPubKey = hex"14eadecaec620fac17b084dcd423b0a75ed2c248b0f73be1bb9b408476567ffc221f420612dd995555650dc19dbe972e7277cb6bfe5ce26650ec907be759b276";
        pcr0 = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        pcr1 = hex"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        pcr2 = hex"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
        maxRPCUrlsPerChain = 10;

        // Deploy and initialize GovernanceEnclave
        GovernanceEnclave implementation = new GovernanceEnclave();
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        governanceEnclave = GovernanceEnclave(address(proxy));

        governanceEnclave.initialize(
            admin,
            kmsPath,
            kmsRootServerPubKey,
            pcr0,
            pcr1,
            pcr2,
            maxRPCUrlsPerChain
        );

        // Initialize MockEnclave and cache values
        mockEnclave = new MockEnclave();
        enclavePubKey = mockEnclave.getEnclavePubKey();
        enclavePrivKey = uint256(bytes32(mockEnclave.getEnclavePrivKey()));
    }

    //-------------------------------- Helpers start --------------------------------//

    /// @dev Helper function to create RPC URLs array
    function _createRpcUrls(uint256 count) internal pure returns (string[] memory) {
        string[] memory urls = new string[](count);
        for (uint256 i = 0; i < count; i++) {
            urls[i] = string(abi.encodePacked(TEST_RPC_URL, "/", vm.toString(i)));
        }
        return urls;
    }

    /// @dev Helper function to setup a basic network config
    function _setupNetwork(uint256 chainId, uint256 rpcCount) internal returns (address tokenAddress) {
        tokenAddress = makeAddr(string(abi.encodePacked("token", vm.toString(chainId))));
        string[] memory rpcUrls = _createRpcUrls(rpcCount);
        
        vm.prank(admin);
        governanceEnclave.setNetworkConfig(chainId, tokenAddress, rpcUrls);
    }

    /// @dev Helper function to convert bytes32 to hex string without '0x' prefix
    function _toHexStringWithNoPrefix(bytes32 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    /// @dev Helper function to sign a message with enclave private key
    function _signWithEnclaveKey(bytes memory message) internal view returns (bytes memory) {
        bytes32 digest = sha256(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(enclavePrivKey, digest);
        return abi.encodePacked(r, s, v);
    }

    //-------------------------------- Helpers end --------------------------------//

    //-------------------------------- Initializer Tests --------------------------------//

    function test_initialize_Success() public view {
        assertEq(governanceEnclave.kmsPath(), kmsPath);
        assertEq(governanceEnclave.kmsRootServerPubKey(), kmsRootServerPubKey);
        assertEq(governanceEnclave.maxRPCUrlsPerChain(), maxRPCUrlsPerChain);
        assertTrue(governanceEnclave.hasRole(governanceEnclave.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_initialize_revert_WhenCalledTwice() public {
        vm.expectRevert("Initializable: contract is already initialized");
        governanceEnclave.initialize(
            admin,
            kmsPath,
            kmsRootServerPubKey,
            pcr0,
            pcr1,
            pcr2,
            maxRPCUrlsPerChain
        );
    }

    function test_initialize_revert_WhenZeroAdmin() public {
        GovernanceEnclave implementation = new GovernanceEnclave();
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), "");
        GovernanceEnclave newEnclave = GovernanceEnclave(address(proxy));

        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidAddress.selector);
        newEnclave.initialize(
            address(0),
            kmsPath,
            kmsRootServerPubKey,
            pcr0,
            pcr1,
            pcr2,
            maxRPCUrlsPerChain
        );
    }

    //-------------------------------- Setters Tests --------------------------------//

    // ========== KMS Path Tests ==========

    function test_setKMSPath_Success() public {
        string memory newPath = "new_governance_path";
        
        vm.prank(admin);
        governanceEnclave.setKMSPath(newPath);

        assertEq(governanceEnclave.kmsPath(), newPath);
    }

    function test_setKMSPath_revert_WhenNotAdmin() public {
        string memory newPath = "new_governance_path";
        
        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.setKMSPath(newPath);
    }

    function test_setKMSPath_revert_WhenEmptyPath() public {
        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidKMSPath.selector);
        governanceEnclave.setKMSPath("");
    }

    // ========== KMS Root Server Key Tests ==========

    function test_setKMSRootServerKey_Success() public {
        bytes memory newKey = hex"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        
        vm.prank(admin);
        governanceEnclave.setKMSRootServerKey(newKey);

        assertEq(governanceEnclave.kmsRootServerPubKey(), newKey);
    }

    function test_setKMSRootServerKey_revert_WhenNotAdmin() public {
        bytes memory newKey = hex"abcdef1234567890";
        
        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.setKMSRootServerKey(newKey);
    }

    function test_setKMSRootServerKey_revert_WhenEmptyKey() public {
        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidKMSRootServerPubKey.selector);
        governanceEnclave.setKMSRootServerKey("");
    }

    // ========== PCR Config Tests ==========

    function test_setPCRConfig_Success() public {
        bytes memory newPcr0 = hex"333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
        bytes memory newPcr1 = hex"444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
        bytes memory newPcr2 = hex"555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
        
        vm.prank(admin);
        governanceEnclave.setPCRConfig(newPcr0, newPcr1, newPcr2);

        (GovernanceEnclave.PCR memory pcr, ) = governanceEnclave.pcrConfig();
        assertEq(pcr.pcr0, newPcr0);
        assertEq(pcr.pcr1, newPcr1);
        assertEq(pcr.pcr2, newPcr2);
    }

    function test_setPCRConfig_revert_WhenNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.setPCRConfig(pcr0, pcr1, pcr2);
    }

    function test_setPCRConfig_revert_WhenEmptyPCR() public {
        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidPCR.selector);
        governanceEnclave.setPCRConfig("", "", "");
    }

    function test_setPCRConfig_revert_WhenSameImageId() public {
        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__SameImageId.selector);
        governanceEnclave.setPCRConfig(pcr0, pcr1, pcr2);
    }

    // ========== Max RPC URLs Per Chain Tests ==========

    function test_setMaxRPCUrlsPerChain_Success() public {
        uint256 newMax = 20;
        
        vm.prank(admin);
        governanceEnclave.setMaxRPCUrlsPerChain(newMax);

        assertEq(governanceEnclave.maxRPCUrlsPerChain(), newMax);
    }

    function test_setMaxRPCUrlsPerChain_revert_WhenNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.setMaxRPCUrlsPerChain(20);
    }

    function test_setMaxRPCUrlsPerChain_revert_WhenZero() public {
        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidMaxRpcUrlsPerChain.selector);
        governanceEnclave.setMaxRPCUrlsPerChain(0);
    }

    // ========== Network Config Tests ==========

    function test_setNetworkConfig_Success() public {
        address tokenAddress = _setupNetwork(TEST_CHAIN_ID, 2);

        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(TEST_CHAIN_ID);
        assertEq(config.tokenAddress, tokenAddress);
        assertEq(config.rpcUrls.length, 2);
    }

    function test_setNetworkConfig_revert_WhenNotAdmin() public {
        string[] memory rpcUrls = _createRpcUrls(1);

        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.setNetworkConfig(TEST_CHAIN_ID, makeAddr("token"), rpcUrls);
    }

    function test_setNetworkConfig_revert_WhenInvalidChainId() public {
        string[] memory rpcUrls = _createRpcUrls(1);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidChainId.selector);
        governanceEnclave.setNetworkConfig(0, makeAddr("token"), rpcUrls);
    }

    function test_setNetworkConfig_revert_WhenEmptyRpcUrls() public {
        string[] memory rpcUrls = new string[](0);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidRpcUrl.selector);
        governanceEnclave.setNetworkConfig(TEST_CHAIN_ID, makeAddr("token"), rpcUrls);
    }

    function test_setNetworkConfig_revert_WhenTooManyRpcUrls() public {
        string[] memory rpcUrls = _createRpcUrls(11); // More than maxRPCUrlsPerChain (10)

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__MaxRpcUrlsPerChainReached.selector);
        governanceEnclave.setNetworkConfig(TEST_CHAIN_ID, makeAddr("token"), rpcUrls);
    }

    function test_setNetworkConfig_RemoveChain() public {
        _setupNetwork(TEST_CHAIN_ID, 1);
        assertEq(governanceEnclave.getSupportedChainIdsLength(), 1);

        // Remove it by setting token address to zero
        string[] memory rpcUrls = _createRpcUrls(1);
        vm.prank(admin);
        governanceEnclave.setNetworkConfig(TEST_CHAIN_ID, address(0), rpcUrls);

        assertEq(governanceEnclave.getSupportedChainIdsLength(), 0);
    }

    // ========== Add RPC URLs Tests ==========

    function test_addRpcUrls_Success() public {
        _setupNetwork(TEST_CHAIN_ID, 1);

        // Add more RPC URLs
        string[] memory newRpcUrls = _createRpcUrls(2);

        vm.prank(admin);
        governanceEnclave.addRpcUrls(TEST_CHAIN_ID, newRpcUrls);

        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(TEST_CHAIN_ID);
        assertEq(config.rpcUrls.length, 3);
    }

    function test_addRpcUrls_revert_WhenNotAdmin() public {
        string[] memory newRpcUrls = _createRpcUrls(1);

        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.addRpcUrls(TEST_CHAIN_ID, newRpcUrls);
    }

    function test_addRpcUrls_revert_WhenChainNotSupported() public {
        string[] memory newRpcUrls = _createRpcUrls(1);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidChainId.selector);
        governanceEnclave.addRpcUrls(999, newRpcUrls);
    }

    function test_addRpcUrls_revert_WhenExceedingMax() public {
        _setupNetwork(TEST_CHAIN_ID, 8);

        // Try to add 3 more (would exceed max of 10)
        string[] memory newRpcUrls = _createRpcUrls(3);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__MaxRpcUrlsPerChainReached.selector);
        governanceEnclave.addRpcUrls(TEST_CHAIN_ID, newRpcUrls);
    }

    // ========== Update RPC URLs At Indexes Tests ==========

    function test_updateRpcUrlsAtIndexes_Success() public {
        _setupNetwork(TEST_CHAIN_ID, 3);

        // Update specific indexes
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 2;
        
        string[] memory newRpcUrls = new string[](2);
        newRpcUrls[0] = "https://newrpc1.example.com";
        newRpcUrls[1] = "https://newrpc3.example.com";

        vm.prank(admin);
        governanceEnclave.updateRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes, newRpcUrls);

        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(TEST_CHAIN_ID);
        assertEq(config.rpcUrls[0], newRpcUrls[0]);
        assertEq(config.rpcUrls[2], newRpcUrls[1]);
    }

    function test_updateRpcUrlsAtIndexes_revert_WhenNotAdmin() public {
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 0;
        string[] memory newRpcUrls = _createRpcUrls(1);

        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.updateRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes, newRpcUrls);
    }

    function test_updateRpcUrlsAtIndexes_revert_WhenLengthMismatch() public {
        _setupNetwork(TEST_CHAIN_ID, 3);

        // Try with mismatched lengths
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 1;
        string[] memory newRpcUrls = _createRpcUrls(1);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidInputLength.selector);
        governanceEnclave.updateRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes, newRpcUrls);
    }

    function test_updateRpcUrlsAtIndexes_revert_WhenInvalidIndex() public {
        _setupNetwork(TEST_CHAIN_ID, 2);

        // Try to update invalid index
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 5; // Out of bounds
        string[] memory newRpcUrls = _createRpcUrls(1);

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidRpcUrlIndex.selector);
        governanceEnclave.updateRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes, newRpcUrls);
    }

    // ========== Remove RPC URLs At Indexes Tests ==========

    function test_removeRpcUrlsAtIndexes_Success() public {
        _setupNetwork(TEST_CHAIN_ID, 5);

        // Remove some URLs
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 1;
        indexes[1] = 3;

        vm.prank(admin);
        governanceEnclave.removeRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes);

        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(TEST_CHAIN_ID);
        assertEq(config.rpcUrls.length, 3);
    }

    function test_removeRpcUrlsAtIndexes_revert_WhenNotAdmin() public {
        uint256[] memory indexes = new uint256[](1);
        indexes[0] = 0;

        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyAdmin.selector);
        governanceEnclave.removeRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes);
    }

    function test_removeRpcUrlsAtIndexes_revert_WhenRemovingAll() public {
        _setupNetwork(TEST_CHAIN_ID, 2);

        // Try to remove all URLs
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 1;

        vm.prank(admin);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__InvalidRpcUrl.selector);
        governanceEnclave.removeRpcUrlsAtIndexes(TEST_CHAIN_ID, indexes);
    }

    //-------------------------------- Getters Tests --------------------------------//

    function test_getImageId() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        assertTrue(imageId != bytes32(0));
    }

    function test_getNetworkHash() public {
        // Initially should be zero
        assertEq(governanceEnclave.getNetworkHash(), bytes32(0));

        // Add a network config
        _setupNetwork(TEST_CHAIN_ID, 1);

        // Now should have a hash
        assertTrue(governanceEnclave.getNetworkHash() != bytes32(0));
    }

    function test_getSupportedChainIdsLength() public {
        assertEq(governanceEnclave.getSupportedChainIdsLength(), 0);

        // Add networks
        for (uint256 i = 1; i <= 3; i++) {
            _setupNetwork(i, 1);
        }

        assertEq(governanceEnclave.getSupportedChainIdsLength(), 3);
    }

    function test_getTokenNetworkConfig() public {
        address tokenAddress = _setupNetwork(TEST_CHAIN_ID, 2);

        GovernanceEnclave.TokenNetworkConfig memory config = governanceEnclave.getTokenNetworkConfig(TEST_CHAIN_ID);
        assertEq(config.tokenAddress, tokenAddress);
        assertEq(config.rpcUrls.length, 2);
        assertTrue(config.chainHash != bytes32(0));
    }

    //-------------------------------- Verification Tests --------------------------------//

    function test_verifyKMSSig_WrongSigner() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        
        // Sign with a different private key (not the KMS root server key)
        uint256 wrongPrivKey = 0x1234567890abcdef;
        string memory uri = string(
            abi.encodePacked(
                "/derive/secp256k1/public?image_id=",
                _toHexStringWithNoPrefix(imageId),
                "&path=governance_test"
            )
        );
        bytes memory message = abi.encodePacked(bytes(uri), enclavePubKey);
        bytes32 messageHash = sha256(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivKey, messageHash);
        bytes memory wrongSig = abi.encodePacked(r, s, v);

        assertFalse(governanceEnclave.verifyKMSSig(imageId, enclavePubKey, wrongSig));
    }

    function test_verifyKMSSig_WrongImageId() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        bytes32 wrongImageId = bytes32(uint256(imageId) + 1);

        assertFalse(governanceEnclave.verifyKMSSig(wrongImageId, enclavePubKey, mockEnclave.getKmsSig()));
    }

    function test_verifyKMSSig_WrongPublicKey() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        bytes memory wrongPubKey = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assertFalse(governanceEnclave.verifyKMSSig(imageId, wrongPubKey, mockEnclave.getKmsSig()));
    }

    function test_verifyEnclaveSig_Valid() public view {
        bytes memory message = abi.encode("test message", uint256(12345));
        bytes memory enclaveSig = _signWithEnclaveKey(message);

        assertTrue(governanceEnclave.verifyEnclaveSig(enclavePubKey, enclaveSig, message));
    }

    function test_verifyEnclaveSig_WrongSigner() public view {
        bytes memory message = abi.encode("test message", uint256(12345));
        
        // Sign with a different private key
        uint256 wrongPrivKey = 0xabcdef1234567890;
        bytes32 digest = sha256(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivKey, digest);
        bytes memory wrongSig = abi.encodePacked(r, s, v);

        assertFalse(governanceEnclave.verifyEnclaveSig(enclavePubKey, wrongSig, message));
    }

    function test_verifyEnclaveSig_WrongMessage() public view {
        bytes memory originalMessage = abi.encode("test message", uint256(12345));
        bytes memory enclaveSig = _signWithEnclaveKey(originalMessage);

        // Try to verify with a different message
        bytes memory differentMessage = abi.encode("different message", uint256(67890));
        assertFalse(governanceEnclave.verifyEnclaveSig(enclavePubKey, enclaveSig, differentMessage));
    }

    function test_verifyEnclaveSig_WrongPublicKey() public view {
        bytes memory message = abi.encode("test message", uint256(12345));
        bytes memory enclaveSig = _signWithEnclaveKey(message);
        bytes memory wrongPubKey = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assertFalse(governanceEnclave.verifyEnclaveSig(wrongPubKey, enclaveSig, message));
    }

    function test_verifyEnclaveSig_Fuzz(bytes memory message) public view {
        bytes memory enclaveSig = _signWithEnclaveKey(message);
        assertTrue(governanceEnclave.verifyEnclaveSig(enclavePubKey, enclaveSig, message));
    }
}

