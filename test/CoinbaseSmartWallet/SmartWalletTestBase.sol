// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Test, console2, stdError} from "forge-std/Test.sol";

import "../../src/CoinbaseSmartWallet.sol";
import {MockCoinbaseSmartWallet} from "../mocks/MockCoinbaseSmartWallet.sol";

contract SmartWalletTestBase is Test {
    CoinbaseSmartWallet public account;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    bytes[] owners;
    IEntryPoint entryPoint = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    address bundler = address(uint160(uint256(keccak256(abi.encodePacked("bundler")))));

    // userOp values
    uint256 userOpNonce;
    bytes userOpCalldata;

    function setUp() public virtual {
        EntryPoint ep = new EntryPoint();
        vm.etch(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108, address(ep).code);
        account = new MockCoinbaseSmartWallet();
        owners.push(abi.encode(signer));
        account.initialize(owners);
    }

    function _sendUserOperation(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        entryPoint.handleOps(ops, payable(bundler));
    }

    function _getUserOp() internal view returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: address(account),
            nonce: userOpNonce,
            initCode: "",
            callData: userOpCalldata,
            accountGasLimits: bytes32(uint256(1_000_000) << 128 | uint256(1_000_000)),
            preVerificationGas: uint256(0),
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _getUserOpWithSignature() internal view returns (PackedUserOperation memory userOp) {
        userOp = _getUserOp();
        userOp.signature = _sign(userOp);
    }

    function _sign(PackedUserOperation memory userOp) internal view virtual returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }

    function _randomBytes(uint256 seed) internal pure returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, seed)
            let r := keccak256(0x00, 0x20)
            if lt(byte(2, r), 0x20) {
                result := mload(0x40)
                let n := and(r, 0x7f)
                mstore(result, n)
                codecopy(add(result, 0x20), byte(1, r), add(n, 0x40))
                mstore(0x40, add(add(result, 0x40), n))
            }
        }
    }
}
