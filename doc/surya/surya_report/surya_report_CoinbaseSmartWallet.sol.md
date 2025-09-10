## Sūrya's Description Report

### Files Description Table


|  File Name  |  SHA-1 Hash  |
|-------------|--------------|
| ./CoinbaseSmartWallet.sol | f2650b33eb763b86da620a2afe64cec125b5e61c |


### Contracts Description Table


|  Contract  |         Type        |       Bases      |                  |                 |
|:----------:|:-------------------:|:----------------:|:----------------:|:---------------:|
|     └      |  **Function Name**  |  **Visibility**  |  **Mutability**  |  **Modifiers**  |
||||||
| **CoinbaseSmartWallet** | Implementation | ERC1271, IAccount, MultiOwnable, UUPSUpgradeable, Receiver |||
| └ | <Constructor> | Public ❗️ | 🛑  |NO❗️ |
| └ | initialize | External ❗️ |  💵 |NO❗️ |
| └ | validateUserOp | External ❗️ | 🛑  | onlyEntryPoint payPrefund |
| └ | executeWithoutChainIdValidation | External ❗️ |  💵 | onlyEntryPoint |
| └ | execute | External ❗️ |  💵 | onlyEntryPointOrOwner |
| └ | executeBatch | External ❗️ |  💵 | onlyEntryPointOrOwner |
| └ | entryPoint | Public ❗️ |   |NO❗️ |
| └ | getUserOpHashWithoutChainId | Public ❗️ |   |NO❗️ |
| └ | implementation | Public ❗️ |   |NO❗️ |
| └ | canSkipChainIdValidation | Public ❗️ |   |NO❗️ |
| └ | _call | Internal 🔒 | 🛑  | |
| └ | _isValidSignature | Internal 🔒 |   | |
| └ | _authorizeUpgrade | Internal 🔒 |   | onlyOwner |
| └ | _domainNameAndVersion | Internal 🔒 |   | |


### Legend

|  Symbol  |  Meaning  |
|:--------:|-----------|
|    🛑    | Function can modify state |
|    💵    | Function is payable |
