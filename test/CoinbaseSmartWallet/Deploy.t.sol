// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

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
    function test_deploy_succeeds() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        vm.prank(signer);
        address deployed = account.deploy(0, bytecode);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
        assertEq(SimpleContract(deployed).deployer(), address(account));
        assertEq(SimpleContract(deployed).ping(), "pong");
    }

    function test_deploy_withValue() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        vm.prank(signer);
        address deployed = account.deploy(0.5 ether, bytecode);

        assertEq(SimpleContract(deployed).value(), 0.5 ether);
        assertEq(deployed.balance, 0.5 ether);
    }

    function test_deploy_emitsEvent() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;

        vm.prank(signer);
        vm.expectEmit(false, true, true, true);
        emit CoinbaseSmartWallet.ContractDeployed(address(0), 0);
        account.deploy(0, bytecode);
    }

    function test_deploy_revertsIfNotOwner() public {
        bytes memory bytecode = type(SimpleContract).creationCode;

        vm.prank(address(0xdead));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.deploy(0, bytecode);
    }

    function test_deploy_revertsOnFailedDeployment() public {
        // Empty bytecode will fail to deploy
        vm.prank(signer);
        vm.expectRevert(CoinbaseSmartWallet.DeploymentFailed.selector);
        account.deploy(0, hex"");
    }

    function test_deployDeterministic_succeeds() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        vm.prank(signer);
        address deployed = account.deployDeterministic(0, bytecode, salt);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
        assertEq(SimpleContract(deployed).deployer(), address(account));
    }

    function test_deployDeterministic_withValue() public {
        vm.deal(address(account), 1 ether);
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        vm.prank(signer);
        address deployed = account.deployDeterministic(0.5 ether, bytecode, salt);

        assertEq(SimpleContract(deployed).value(), 0.5 ether);
        assertEq(deployed.balance, 0.5 ether);
    }

    function test_deployDeterministic_addressIsDeterministic() public {
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        // Compute expected address
        address expected =
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(account), salt, keccak256(bytecode))))));

        vm.prank(signer);
        address deployed = account.deployDeterministic(0, bytecode, salt);

        assertEq(deployed, expected);
    }

    function test_deployDeterministic_revertsIfNotOwner() public {
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        vm.prank(address(0xdead));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.deployDeterministic(0, bytecode, salt);
    }

    function test_deployDeterministic_revertsOnSameSaltTwice() public {
        bytes memory bytecode = type(SimpleContract).creationCode;
        bytes32 salt = bytes32(uint256(42));

        vm.startPrank(signer);
        account.deployDeterministic(0, bytecode, salt);

        vm.expectRevert(CoinbaseSmartWallet.DeploymentFailed.selector);
        account.deployDeterministic(0, bytecode, salt);
    }
}
