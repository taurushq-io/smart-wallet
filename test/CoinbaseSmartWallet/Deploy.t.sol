// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Vm} from "forge-std/Vm.sol";
import "./SmartWalletTestBase.sol";

/// @dev Simple contract used to test deployment
contract SimpleContract {
    address public deployer;
    uint256 public value;

    constructor() payable {
        deployer = msg.sender;
        value = msg.value;
    }

    function ping() external pure returns (string memory) {
        return "pong";
    }
}

contract TestDeploy is SmartWalletTestBase {
    /// @dev ContractDeployed(address indexed deployed, uint256 value)
    bytes32 constant CONTRACT_DEPLOYED_SIG = keccak256("ContractDeployed(address,uint256)");
    /// @dev UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)
    bytes32 constant USER_OP_REVERT_SIG = keccak256("UserOperationRevertReason(bytes32,address,uint256,bytes)");

    /// @dev Override _sign to produce a properly ABI-encoded SignatureWrapper
    ///      that _isValidSignature can decode.
    function _sign(PackedUserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({ownerIndex: 0, signatureData: abi.encodePacked(r, s, v)})
        );
    }

    function _getDeployedAddress(Vm.Log[] memory logs) internal pure returns (address deployed) {
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics.length > 1 && logs[i].topics[0] == CONTRACT_DEPLOYED_SIG) {
                deployed = address(uint160(uint256(logs[i].topics[1])));
                return deployed;
            }
        }
        revert("ContractDeployed event not found");
    }

    function _hasRevertEvent(Vm.Log[] memory logs) internal pure returns (bool) {
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == USER_OP_REVERT_SIG) {
                return true;
            }
        }
        return false;
    }

    function test_deploy_succeeds() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deploy, (0, bytecode));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
        assertEq(SimpleContract(deployed).deployer(), address(account));
        assertEq(SimpleContract(deployed).ping(), "pong");
    }

    function test_deploy_withValue() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deploy, (0.5 ether, bytecode));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);

        assertEq(SimpleContract(deployed).value(), 0.5 ether);
        assertEq(deployed.balance, 0.5 ether);
    }

    function test_deploy_emitsEvent() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deploy, (0, bytecode));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);
        assertTrue(deployed != address(0));
    }

    function test_deploy_revertsIfNotOwner() public {
        bytes memory bytecode = type(SimpleContract).creationCode;

        // Build UserOp signed by a non-owner key
        uint256 nonOwnerKey = 0xbad;
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deploy, (0, bytecode));
        PackedUserOperation memory userOp = _getUserOp();
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonOwnerKey, toSign);
        userOp.signature = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({ownerIndex: 0, signatureData: abi.encodePacked(r, s, v)})
        );

        vm.expectRevert();
        _sendUserOperation(userOp);
    }

    function test_deploy_revertsOnFailedDeployment() public {
        vm.deal(address(account), 1 ether);

        // Empty bytecode — inner call reverts but EntryPoint catches it
        // and emits UserOperationRevertReason instead of reverting handleOps
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deploy, (0, hex""));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_hasRevertEvent(logs), "Expected UserOperationRevertReason event");
    }

    function test_deployDeterministic_succeeds() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0, bytecode, salt));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
        assertEq(SimpleContract(deployed).deployer(), address(account));
    }

    function test_deployDeterministic_withValue() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0.5 ether, bytecode, salt));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);

        assertEq(SimpleContract(deployed).value(), 0.5 ether);
        assertEq(deployed.balance, 0.5 ether);
    }

    function test_deployDeterministic_addressIsDeterministic() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        // Compute expected CREATE2 address
        address expected =
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(account), salt, keccak256(bytecode))))));

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0, bytecode, salt));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        address deployed = _getDeployedAddress(logs);

        assertEq(deployed, expected);
    }

    function test_deployDeterministic_revertsIfNotOwner() public {
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        // Build UserOp signed by a non-owner key
        uint256 nonOwnerKey = 0xbad;
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0, bytecode, salt));
        PackedUserOperation memory userOp = _getUserOp();
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonOwnerKey, toSign);
        userOp.signature = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({ownerIndex: 0, signatureData: abi.encodePacked(r, s, v)})
        );

        vm.expectRevert();
        _sendUserOperation(userOp);
    }

    function test_deployDeterministic_revertsOnSameSaltTwice() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        // First deploy succeeds
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0, bytecode, salt));
        _sendUserOperation(_getUserOpWithSignature());

        // Second deploy with same salt — inner call reverts,
        // EntryPoint emits UserOperationRevertReason
        userOpNonce = 1;
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.deployDeterministic, (0, bytecode, salt));
        vm.recordLogs();
        _sendUserOperation(_getUserOpWithSignature());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_hasRevertEvent(logs), "Expected UserOperationRevertReason event");
    }
}
