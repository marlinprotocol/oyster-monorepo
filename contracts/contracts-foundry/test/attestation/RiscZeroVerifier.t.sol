// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {RiscZeroVerifier, RiscZeroVerifierDefault} from "../../src/attestation/RiscZeroVerifier.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";

contract TestRiscZeroVerifier is RiscZeroVerifierDefault {
    bool public authorized;

    error NotAuthorized();

    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bool _authorized
    ) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) {
        authorized = _authorized;
    }

    function setAuthorized(bool _authorized) external {
        authorized = _authorized;
    }

    function _rzvAuthorizeUpdate() internal virtual override {
        require(authorized, NotAuthorized());
    }

    function verify(bytes calldata _seal, IAttestationVerifier.Attestation calldata _attestation) external view {
        return _verify(_seal, _attestation);
    }
}

contract RiscZeroVerifierTestConstruction is Test {
    function test_Construction(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAgeMs)
        public
    {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, 0);

        TestRiscZeroVerifier _riscZeroVerifier =
            new TestRiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs, true);

        assertEq(address(_riscZeroVerifier.verifier()), address(_verifier));
        assertEq(_riscZeroVerifier.guestId(), _guestId);
        assertEq(_riscZeroVerifier.rootKey(), _rootKey);
        assertEq(_riscZeroVerifier.maxAgeMs(), _maxAgeMs);
    }
}

contract RiscZeroVerifierTestUpdateVerifier is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateVerifier_Authorized(IRiscZeroVerifier _verifier) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, verifier);

        riscZeroVerifier.updateVerifier(_verifier);

        assertEq(address(riscZeroVerifier.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_Unauthorized(IRiscZeroVerifier _verifier) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateVerifier(_verifier);
    }
}

contract RiscZeroVerifierTestUpdateGuestId is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateGuestId_Authorized(bytes32 _guestId) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, guestId);

        riscZeroVerifier.updateGuestId(_guestId);

        assertEq(riscZeroVerifier.guestId(), _guestId);
    }

    function test_UpdateGuestId_Unauthorized(bytes32 _guestId) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateGuestId(_guestId);
    }
}

contract RiscZeroVerifierTestUpdateRootKey is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateRootKey_Authorized(bytes calldata _rootKey) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);

        riscZeroVerifier.updateRootKey(_rootKey);

        assertEq(riscZeroVerifier.rootKey(), _rootKey);
    }

    function test_UpdateRootKey_Unauthorized(bytes calldata _rootKey) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateRootKey(_rootKey);
    }
}

contract RiscZeroVerifierTestUpdateMaxAge is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateMaxAge_Authorized(uint256 _maxAgeMs) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, maxAgeMs);

        riscZeroVerifier.updateMaxAge(_maxAgeMs);

        assertEq(riscZeroVerifier.maxAgeMs(), _maxAgeMs);
    }

    function test_UpdateMaxAge_Unauthorized(uint256 _maxAgeMs) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateMaxAge(_maxAgeMs);
    }
}

contract RiscZeroVerifierTestVerify is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_Verify_Valid(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length < 256);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampMs, _imageId, rootKey, uint8(_pubkey.length), _pubkey, uint16(_userData.length), _userData
            )
        );
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        vm.warp(4);

        riscZeroVerifier.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, _userData));
    }

    function test_Verify_TooOld(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length < 256);
        _timestampMs = uint64(bound(_timestampMs, 0, 2000));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierTooOld.selector));
        vm.warp(4);

        riscZeroVerifier.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, _userData));
    }

    function test_Verify_PubkeyTooLong(
        bytes calldata _seal,
        bytes memory _pubkey,
        bytes calldata _userData,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        // foundry does not generate data >256 length, concat to emulate it
        vm.assume(_pubkey.length > 64);
        _pubkey = bytes.concat(_pubkey, _pubkey, _pubkey, _pubkey);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierPubkeyTooLong.selector));
        vm.warp(4);

        riscZeroVerifier.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, _userData));
    }

    function test_Verify_UserDataTooLong(
        bytes calldata _seal,
        bytes memory _pubkey,
        bytes memory _userData,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length < 256);
        // foundry does not generate data >65536 length, concat to emulate it
        vm.assume(_userData.length > 64);
        _userData = bytes.concat(_userData, _userData, _userData, _userData); // 256
        _userData = bytes.concat(_userData, _userData, _userData, _userData); // 1024
        _userData = bytes.concat(_userData, _userData, _userData, _userData); // 4096
        _userData = bytes.concat(_userData, _userData, _userData, _userData); // 16384
        _userData = bytes.concat(_userData, _userData, _userData, _userData); // 65536
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierUserDataTooLong.selector));
        vm.warp(4);

        riscZeroVerifier.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, _userData));
    }

    function test_Verify_InvalidSeal(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes calldata _userData,
        bytes32 _imageId,
        uint64 _timestampMs
    ) public {
        vm.assume(_pubkey.length < 256);
        _timestampMs = uint64(bound(_timestampMs, 2001, type(uint64).max));
        vm.mockCallRevert(address(verifier), abi.encode(), "0x12345678");
        vm.expectRevert("0x12345678");
        vm.warp(4);

        riscZeroVerifier.verify(_seal, IAttestationVerifier.Attestation(_imageId, _timestampMs, _pubkey, _userData));
    }
}
