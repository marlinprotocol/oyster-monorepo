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
        kmsRootServerPubKey = hex"d8ad28c9f74e8bf4eb9199e638b2df049282e9c28e40edd096b443ef95b3b829ed785629e1aab7ce66459c76c9888ea26a8eae3a401ac6532824bde249b3292e";
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
        assertEq(governanceEnclave.kmsRootServerPubKey(), kmsRootServerPubKey);
        assertEq(governanceEnclave.maxRPCUrlsPerChain(), maxRPCUrlsPerChain);
        assertTrue(governanceEnclave.hasRole(governanceEnclave.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_initialize_revert_WhenCalledTwice() public {
        vm.expectRevert("Initializable: contract is already initialized");
        governanceEnclave.initialize(
            admin,
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
            kmsRootServerPubKey,
            pcr0,
            pcr1,
            pcr2,
            maxRPCUrlsPerChain
        );
    }

    //-------------------------------- Setters Tests --------------------------------//

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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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

        (bytes memory retPcr0, bytes memory retPcr1, bytes memory retPcr2,) = governanceEnclave.getPCRConfig();
        assertEq(retPcr0, newPcr0);
        assertEq(retPcr1, newPcr1);
        assertEq(retPcr2, newPcr2);
    }

    function test_setPCRConfig_revert_WhenNotAdmin() public {
        vm.prank(user);
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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
        vm.expectRevert(GovernanceEnclave.GovernanceEnclave__OnlyDefaultAdmin.selector);
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

    function test_getSupportedChainIds_Empty() public view {
        uint256[] memory chainIds = governanceEnclave.getAllSupportedChainIds();
        assertEq(chainIds.length, 0, "Should have no supported chains initially");
    }

    function test_getSupportedChainIds_Multiple() public {
        // Add multiple networks
        _setupNetwork(1, 1);
        _setupNetwork(2, 1);
        _setupNetwork(3, 1);

        uint256[] memory chainIds = governanceEnclave.getAllSupportedChainIds();
        assertEq(chainIds.length, 3, "Should have 3 supported chains");
        
        // Verify chain IDs are correct (order might not be guaranteed)
        bool hasChain1 = false;
        bool hasChain2 = false;
        bool hasChain3 = false;
        
        for (uint256 i = 0; i < chainIds.length; i++) {
            if (chainIds[i] == 1) hasChain1 = true;
            if (chainIds[i] == 2) hasChain2 = true;
            if (chainIds[i] == 3) hasChain3 = true;
        }
        
        assertTrue(hasChain1, "Should contain chain 1");
        assertTrue(hasChain2, "Should contain chain 2");
        assertTrue(hasChain3, "Should contain chain 3");
    }

    function test_getSupportedChainIds_AfterRemoval() public {
        // Add networks
        _setupNetwork(1, 1);
        _setupNetwork(2, 1);
        
        assertEq(governanceEnclave.getAllSupportedChainIds().length, 2, "Should have 2 chains");
        
        // Remove one network by setting token to address(0)
        string[] memory emptyUrls = new string[](1);
        emptyUrls[0] = "https://placeholder.com";
        
        vm.prank(admin);
        governanceEnclave.setNetworkConfig(1, address(0), emptyUrls);
        
        uint256[] memory chainIds = governanceEnclave.getAllSupportedChainIds();
        assertEq(chainIds.length, 1, "Should have 1 chain after removal");
        assertEq(chainIds[0], 2, "Should only have chain 2");
    }

    function test_isChainSupported_True() public {
        _setupNetwork(TEST_CHAIN_ID, 1);
        assertTrue(governanceEnclave.isChainSupported(TEST_CHAIN_ID), "Chain should be supported");
    }

    function test_isChainSupported_False() public view {
        assertFalse(governanceEnclave.isChainSupported(999), "Chain should not be supported");
    }

    function test_isChainSupported_Multiple() public {
        _setupNetwork(1, 1);
        _setupNetwork(2, 1);
        _setupNetwork(5, 1);
        
        assertTrue(governanceEnclave.isChainSupported(1), "Chain 1 should be supported");
        assertTrue(governanceEnclave.isChainSupported(2), "Chain 2 should be supported");
        assertFalse(governanceEnclave.isChainSupported(3), "Chain 3 should not be supported");
        assertFalse(governanceEnclave.isChainSupported(4), "Chain 4 should not be supported");
        assertTrue(governanceEnclave.isChainSupported(5), "Chain 5 should be supported");
    }

    function test_isChainSupported_AfterRemoval() public {
        _setupNetwork(TEST_CHAIN_ID, 1);
        assertTrue(governanceEnclave.isChainSupported(TEST_CHAIN_ID), "Chain should be supported");
        
        // Remove network
        string[] memory emptyUrls = new string[](1);
        emptyUrls[0] = "https://placeholder.com";
        
        vm.prank(admin);
        governanceEnclave.setNetworkConfig(TEST_CHAIN_ID, address(0), emptyUrls);
        
        assertFalse(governanceEnclave.isChainSupported(TEST_CHAIN_ID), "Chain should not be supported after removal");
    }

    function test_getPCRConfig_ReturnsCorrectValues() public view {
        (bytes memory returnedPcr0, bytes memory returnedPcr1, bytes memory returnedPcr2, bytes32 returnedImageId) 
            = governanceEnclave.getPCRConfig();
        
        assertEq(returnedPcr0, pcr0, "PCR0 should match");
        assertEq(returnedPcr1, pcr1, "PCR1 should match");
        assertEq(returnedPcr2, pcr2, "PCR2 should match");
        assertEq(returnedImageId, governanceEnclave.getImageId(), "ImageId should match getImageId()");
    }

    function test_getPCRConfig_AfterUpdate() public {
        // Update PCR config
        bytes memory newPcr0 = hex"333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
        bytes memory newPcr1 = hex"444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
        bytes memory newPcr2 = hex"555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
        
        vm.prank(admin);
        governanceEnclave.setPCRConfig(newPcr0, newPcr1, newPcr2);
        
        (bytes memory returnedPcr0, bytes memory returnedPcr1, bytes memory returnedPcr2, bytes32 returnedImageId) 
            = governanceEnclave.getPCRConfig();
        
        assertEq(returnedPcr0, newPcr0, "PCR0 should be updated");
        assertEq(returnedPcr1, newPcr1, "PCR1 should be updated");
        assertEq(returnedPcr2, newPcr2, "PCR2 should be updated");
        assertTrue(returnedImageId != bytes32(0), "ImageId should be generated");
        assertEq(returnedImageId, governanceEnclave.getImageId(), "ImageId should match getImageId()");
    }

    //-------------------------------- Verification Tests --------------------------------//

    function test_verifyKMSSig_WrongSigner() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        bytes32 proposalId = bytes32(uint256(1));
        
        // Sign with a different private key (not the KMS root server key)
        uint256 wrongPrivKey = 0x1234567890abcdef;
        string memory uri = string(
            abi.encodePacked(
                "/derive/secp256k1/public?image_id=",
                _toHexStringWithNoPrefix(imageId),
                "&path=",
                _toHexStringWithNoPrefix(proposalId),
                "_result"
            )
        );
        bytes memory message = abi.encodePacked(bytes(uri), enclavePubKey);
        bytes32 messageHash = sha256(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivKey, messageHash);
        bytes memory wrongSig = abi.encodePacked(r, s, v);

        assertFalse(governanceEnclave.verifyKMSSig(imageId, enclavePubKey, wrongSig, proposalId));
    }

    function test_verifyKMSSig_WrongImageId() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        bytes32 wrongImageId = bytes32(uint256(imageId) + 1);
        bytes32 proposalId = bytes32(uint256(1));

        // Sign with correct imageId but verify with wrong imageId
        assertFalse(governanceEnclave.verifyKMSSig(wrongImageId, enclavePubKey, mockEnclave.getKmsSig(imageId, proposalId), proposalId));
    }

    function test_verifyKMSSig_WrongPublicKey() public view {
        bytes32 imageId = governanceEnclave.getImageId();
        bytes32 proposalId = bytes32(uint256(1));
        bytes memory wrongPubKey = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assertFalse(governanceEnclave.verifyKMSSig(imageId, wrongPubKey, mockEnclave.getKmsSig(imageId, proposalId), proposalId));
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

