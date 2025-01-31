// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract KmsRootTestConstruction is Test {
    function test_Construction(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        bytes memory _rootKey,
        uint256 _maxAge
    ) public {
        vm.assume(_owner != address(0));

        vm.expectEmit();
        emit Ownable.OwnershipTransferred(address(0), _owner);

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedVerifier(
            _verifier,
            IRiscZeroVerifier(address(0))
        );

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedImageId(_imageId, bytes32(0));

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedPcrs(_pcrs, new bytes(0));

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedRootKey(_rootKey, new bytes(0));

        KmsRoot _kmsRoot = new KmsRoot(
            _owner,
            _verifier,
            _imageId,
            _pcrs,
            _rootKey,
            _maxAge
        );

        assertEq(_kmsRoot.owner(), _owner);
        assertEq(address(_kmsRoot.verifier()), address(_verifier));
        assertEq(_kmsRoot.imageId(), _imageId);
        assertEq(_kmsRoot.pcrs(), _pcrs);
        assertEq(_kmsRoot.rootKey(), _rootKey);
        assertEq(_kmsRoot.MAX_AGE(), _maxAge);
    }
}

contract KmsRootTestUpdateVerifier is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48 * 3);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdateVerifier_FromOwner(IRiscZeroVerifier _verifier) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedVerifier(_verifier, verifier);

        kmsRoot.updateVerifier(_verifier);

        assertEq(address(kmsRoot.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_FromNonOwner(
        IRiscZeroVerifier _verifier,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updateVerifier(_verifier);
    }
}

contract KmsRootTestUpdateImageId is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48 * 3);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdateImageId_FromOwner(bytes32 _imageId) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedImageId(_imageId, imageId);

        kmsRoot.updateImageId(_imageId);

        assertEq(kmsRoot.imageId(), _imageId);
    }

    function test_UpdateImageId_FromNonOwner(
        bytes32 _imageId,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updateImageId(_imageId);
    }
}

contract KmsRootTestUpdatePcrs is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48 * 3);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdatePcrs_FromOwner(bytes calldata _pcrs) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedPcrs(_pcrs, pcrs);

        kmsRoot.updatePcrs(_pcrs);

        assertEq(kmsRoot.pcrs(), _pcrs);
    }

    function test_UpdatePcrs_FromNonOwner(
        bytes calldata _pcrs,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updatePcrs(_pcrs);
    }
}

contract KmsRootTestUpdateRootKey is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48 * 3);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdateRootKey_FromOwner(bytes calldata _rootKey) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedRootKey(_rootKey, rootKey);

        kmsRoot.updateRootKey(_rootKey);

        assertEq(kmsRoot.rootKey(), _rootKey);
    }

    function test_UpdateRootKey_FromNonOwner(
        bytes calldata _rootKey,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updateRootKey(_rootKey);
    }
}

contract KmsRootTestVerify is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48 * 3);
        rootKey = vm.randomBytes(48);
        maxAge = 2;
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_Verify_Valid(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_signerPubkey.length == 64);
        _timestampInMilliseconds = uint64(
            bound(_timestampInMilliseconds, 2001, type(uint64).max)
        );
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampInMilliseconds,
                pcrs,
                rootKey,
                uint8(64),
                _signerPubkey,
                uint16(0)
            )
        );
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata = abi.encodeWithSelector(
            IRiscZeroVerifier.verify.selector,
            _seal,
            imageId,
            _journalDigest
        );
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        address _addr = address(uint160(uint256(keccak256(_signerPubkey))));
        vm.expectEmit();
        emit KmsRoot.KmsRootVerified(_addr);
        vm.warp(4);

        kmsRoot.verify(_signerPubkey, _seal, _timestampInMilliseconds);

        assertTrue(kmsRoot.isVerified(_addr));
    }

    function test_Verify_TooOld(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_signerPubkey.length == 64);
        _timestampInMilliseconds = uint64(
            bound(_timestampInMilliseconds, 0, 2000)
        );
        vm.expectRevert(abi.encodeWithSelector(KmsRoot.KmsRootTooOld.selector));
        vm.warp(4);

        kmsRoot.verify(_signerPubkey, _seal, _timestampInMilliseconds);
    }

    function test_Verify_InvalidLength(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_signerPubkey.length != 64);
        _timestampInMilliseconds = uint64(
            bound(_timestampInMilliseconds, 2001, type(uint64).max)
        );
        vm.expectRevert(
            abi.encodeWithSelector(KmsRoot.KmsRootLengthInvalid.selector)
        );
        vm.warp(4);

        kmsRoot.verify(_signerPubkey, _seal, _timestampInMilliseconds);
    }

    function test_Verify_InvalidSeal(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_signerPubkey.length == 64);
        _timestampInMilliseconds = uint64(
            bound(_timestampInMilliseconds, 2001, type(uint64).max)
        );
        vm.mockCallRevert(address(verifier), abi.encode(), "0x12345678");
        vm.expectRevert("0x12345678");
        vm.warp(4);

        kmsRoot.verify(_signerPubkey, _seal, _timestampInMilliseconds);
    }
}
