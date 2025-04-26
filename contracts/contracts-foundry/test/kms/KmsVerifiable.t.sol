// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {KmsVerifiable} from "../../src/kms/KmsVerifiable.sol";

contract KmsVerifiableTestConstructor is Test {
    function test_construction() public {
        bytes32[] memory _imageIds = new bytes32[](1);
        address _owner = makeAddr("owner");
        vm.prank(_owner);
        _imageIds[0] = bytes32(vm.randomUint());
        vm.expectEmit();
        emit KmsVerifiable.ImageApproved(_imageIds[0]);
        KmsVerifiable _kms = new KmsVerifiable(_imageIds);
        assertEq(_kms.owner(), _owner);
        assertTrue(_kms.images(_imageIds[0]));
    }
}

contract KmsVerifiableTest is Test {
    address owner;
    bytes32[] imageIds;
    KmsVerifiable kmsVerifiable;

    function setUp() public {
        owner = makeAddr("owner");
        vm.prank(owner);
        imageIds = new bytes32[](1);
        imageIds[0] = bytes32(vm.randomUint());
        kmsVerifiable = new KmsVerifiable(imageIds);
    }

    function test_verifyImage() public view {
        // Execute
        bytes32 imageId = imageIds[0];
        bool result = kmsVerifiable.oysterKMSVerify(imageId);
        // Validate
        assertTrue(result);
    }

    function test_approveImages(bytes32[] calldata _imageIds) public {
        // Execute
        vm.prank(owner);
        for (uint256 i = 0; i < _imageIds.length; i++) {
            vm.expectEmit();
            emit KmsVerifiable.ImageApproved(_imageIds[i]);
        }
        kmsVerifiable.approveImages(_imageIds);
        // Validate
        for (uint256 i = 0; i < _imageIds.length; i++) {
            assertTrue(kmsVerifiable.images(_imageIds[i]));
        }

        // approve the same images again
        vm.prank(owner);
        for (uint256 i = 0; i < _imageIds.length; i++) {
            vm.expectEmit();
            emit KmsVerifiable.ImageApproved(_imageIds[i]);
        }
        kmsVerifiable.approveImages(_imageIds);
        for (uint256 i = 0; i < _imageIds.length; i++) {
            assertTrue(kmsVerifiable.images(_imageIds[i]));
        }
    }

    function test_revokeImages() public {
        // Execute
        vm.prank(owner);
        for (uint256 i = 0; i < imageIds.length; i++) {
            vm.expectEmit();
            emit KmsVerifiable.ImageRevoked(imageIds[i]);
        }
        kmsVerifiable.revokeImages(imageIds);
        // Validate
        for (uint256 i = 0; i < imageIds.length; i++) {
            assertFalse(kmsVerifiable.images(imageIds[i]));
        }

        // revoke the same images again
        vm.prank(owner);
        for (uint256 i = 0; i < imageIds.length; i++) {
            vm.expectEmit();
            emit KmsVerifiable.ImageRevoked(imageIds[i]);
        }
        kmsVerifiable.revokeImages(imageIds);
        for (uint256 i = 0; i < imageIds.length; i++) {
            assertFalse(kmsVerifiable.images(imageIds[i]));
        }
    }
}
