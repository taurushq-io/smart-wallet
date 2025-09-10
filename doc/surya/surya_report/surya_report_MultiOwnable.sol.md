## Sūrya's Description Report

### Files Description Table


|  File Name  |  SHA-1 Hash  |
|-------------|--------------|
| ./MultiOwnable.sol | 4e74646c3bdd5a25a989cfb679637648a7abace8 |


### Contracts Description Table


|  Contract  |         Type        |       Bases      |                  |                 |
|:----------:|:-------------------:|:----------------:|:----------------:|:---------------:|
|     └      |  **Function Name**  |  **Visibility**  |  **Mutability**  |  **Modifiers**  |
||||||
| **MultiOwnable** | Implementation |  |||
| └ | addOwnerAddress | External ❗️ | 🛑  | onlyOwner |
| └ | addOwnerPublicKey | External ❗️ | 🛑  | onlyOwner |
| └ | removeOwnerAtIndex | External ❗️ | 🛑  | onlyOwner |
| └ | removeLastOwner | External ❗️ | 🛑  | onlyOwner |
| └ | isOwnerAddress | Public ❗️ |   |NO❗️ |
| └ | isOwnerPublicKey | Public ❗️ |   |NO❗️ |
| └ | isOwnerBytes | Public ❗️ |   |NO❗️ |
| └ | ownerAtIndex | Public ❗️ |   |NO❗️ |
| └ | nextOwnerIndex | Public ❗️ |   |NO❗️ |
| └ | ownerCount | Public ❗️ |   |NO❗️ |
| └ | removedOwnersCount | Public ❗️ |   |NO❗️ |
| └ | _initializeOwners | Internal 🔒 | 🛑  | |
| └ | _addOwnerAtIndex | Internal 🔒 | 🛑  | |
| └ | _removeOwnerAtIndex | Internal 🔒 | 🛑  | |
| └ | _checkOwner | Internal 🔒 |   | |
| └ | _getMultiOwnableStorage | Internal 🔒 |   | |


### Legend

|  Symbol  |  Meaning  |
|:--------:|-----------|
|    🛑    | Function can modify state |
|    💵    | Function is payable |
