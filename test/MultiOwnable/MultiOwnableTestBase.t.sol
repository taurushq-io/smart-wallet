// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console2, stdError} from "forge-std/Test.sol";

import "../mocks/MockMultiOwnable.sol";

contract MultiOwnableTestBase is Test {
    MockMultiOwnable mock = new MockMultiOwnable();
    address owner1Address = address(0xb0b);
    bytes owner1Bytes = abi.encode(owner1Address);
    address owner2Address = address(0xa11ce);
    bytes owner2Bytes = abi.encode(owner2Address);
    bytes[] owners;

    function setUp() public virtual {
        owners.push(owner1Bytes);
        owners.push(owner2Bytes);
        mock.init(owners);
    }
}
