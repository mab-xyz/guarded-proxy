# Guarded Proxy Pattern for Smart Contracts

Author: mab.xyz

## Abstract

The Guarded Proxy pattern implements operation-level access control for delegatecall-based
contract interactions. Unlike traditional proxy patterns that forward all calls unconditionally,
or access control patterns that restrict WHO can call, this pattern restricts WHAT operations
can be executed by maintaining an allowlist of function selectors. 
  
When a call is received, the proxy extracts the function selector 
and verifies it against an admin-controlled allowlist mapping before executing the delegatecall.
This enables use cases such as: progressive feature rollouts, sandboxed contract testing,
restricted smart contract wallets, compliance-controlled DeFi access, and gradual protocol
migrations. The pattern provides a trust-minimized mechanism for selectively exposing contract
functionality while maintaining the execution context benefits of delegatecall.
 
## Motivation

Current Ethereum smart contract designs provide either **full delegation** or **caller-based restrictions**, but lack granular **operation-level control**. This creates significant security and usability gaps:

**1. Traditional Proxy Patterns Are All-or-Nothing**
Standard proxy patterns (Transparent, UUPS, Beacon) forward every function call to the implementation contract without discrimination. Once you deploy a proxy pointing to an implementation, users can call ANY function that exists in that implementation. This creates several problems:

- **Unvetted Feature Exposure**: New implementation versions may contain experimental or unaudited functions that are immediately accessible
- **No Staged Rollouts**: Cannot gradually enable features - it's all functions or none
- **Attack Surface Expansion**: Every function in the implementation becomes an attack vector simultaneously
- **No Emergency Granularity**: If one function is exploited, you must disable the entire contract

**2. Access Control Patterns Focus on "Who", Not "What"**

Existing access control mechanisms (Ownable, AccessControl, Role-Based) restrict WHO can call functions, but assume that authorized callers should access ALL functionality:

- **Coarse Permissions**: "Admin" role typically grants access to all admin functions
- **Cannot Limit Trusted Parties**: Even trusted signers in a multisig can call dangerous functions
- **No Function Isolation**: Cannot say "this wallet can swap but not transfer ownership"
- **Trust Assumptions**: Requires complete trust in anyone with elevated permissions

## Elaborated Use Cases

### **Smart Contract Wallets with Protection**

Scenario: A smart contract wallet that protects the user funds
- Wallet holds user funds (ETH, tokens)
- BUT only specific functions are allowed (transfer, swap, stake)
- Blocked: Self-destruct, arbitrary calls, admin backdoors, degen protocols
- The owner can allowlist or delegate the allow list to a third-party

Example: Parent gives child a crypto wallet with limited capabilities
- Can only: Send to allowlisted addresses, swap tokens, stake
- Cannot: Transfer large amounts, interact with risky DeFi, change ownership


### **DAO Treasury with Staged Permissions**

Scenario: DAO wants to try new strategies and protocols without full risk exposure
- Treasury wrapper holds DAO funds
- DAO votes to allowlist specific strategy functions
- Can enable: stake(), unstake(), claimRewards()
- Blocked by default: emergencyWithdraw(), migrate()

### **Multi-Signature Wallet with Role-Based Execution**

Scenario: Different signers have different permissions
- Low-permission signers can only call allowlisted functions
- High-permission signers can modify allowlist
- Functions exposed: Daily operations (transfers, approvals)
- Functions blocked: Admin operations (upgrade, ownership transfer)

Corporate treasury example:
- CFO: Can approve payments, token transfers
- CEO: Can modify allowlist, add new integrations
- Accountant: Can only view balances, generate reports


### **Gradual Feature Rollout System**

Scenario: Protocol wants to roll out features incrementally
- Start with core features allowlisted
- Monitor usage and security
- Gradually allowlist more advanced features
- Can instantly disable problematic features

DeFi protocol example:
Phase 1: Basic swap() only
Phase 2: Add addLiquidity(), removeLiquidity()
Phase 3: Add flashLoan() after security review
Phase 4: Add governance functions
- If exploit found in Phase 3, instantly remove from allowlist


### **Institutional Compliance-Restricted DeFi Access**

Scenario: Regulated entities need controlled DeFi access
- Financial institution wants DeFi yields
- Compliance requires: No anonymous protocols, no high-risk operations
- Wrapper ensures: Only approved protocols, only vetted functions
- Audit trail: All operations logged and verifiable

Example limitations:
✓ Allowed: Staking in audited protocols, swap major tokens
✗ Blocked: Privacy protocols, leveraged positions, exotic derivatives


### **Child/TeenagerAccount System**

Scenario: Give limited access to others without full control
- Parent/main account wraps its capabilities
- Child/dependent can only use allowlisted functions
- Example: Allowance system with smart limits

Use case - Crypto allowance for teenager:
- Can spend up to X per week (allowlisted spend function)
- Can stake in safe protocols (allowlisted stake functions)
- Cannot: Access principal, use high-risk DeFi, transfer to unknown addresses


### **Emergency Pause with Selective Recovery**

Scenario: Protocol exploit detected, need surgical response
- Wrapper can instantly disable all functions
- Selectively re-enable safe functions
- Allow users to withdraw funds via specific paths only

Post-exploit recovery:
1. Remove all functions from allowlist (full pause)
2. Analyze which functions are safe
3. Re-allowlist only: Emergency withdraw, view functions
4. Gradual restoration as security is confirmed

## Specification

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IGuardedProxy
 * @notice Interface for the Guarded Proxy pattern
 * @dev Implements operation-level access control for delegatecall-based contract interactions
 */
interface IGuardedProxy {
    
    // ============ Events ============
    
    /**
     * @notice Emitted when a function selector is added to the allowlist
     * @param target The contract address whose function is being allowlisted
     * @param selector The 4-byte function selector being allowlisted
     */
    event FunctionAllowlisted(address indexed target, bytes4 indexed selector);
    
    /**
     * @notice Emitted when a function selector is removed from the allowlist
     * @param target The contract address whose function is being removed
     * @param selector The 4-byte function selector being removed
     */
    event FunctionRemovedFromAllowlist(address indexed target, bytes4 indexed selector);
    
    /**
     * @notice Emitted when a delegatecall is successfully executed
     * @param target The contract address that was delegatecalled
     * @param selector The 4-byte function selector that was executed
     * @param success Whether the delegatecall succeeded
     */
    event DelegatecallExecuted(address indexed target, bytes4 indexed selector, bool success);
    
    /**
     * @notice Emitted when contract ownership is transferred
     * @param previousOwner The address of the previous owner
     * @param newOwner The address of the new owner
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    /**
     * @notice Emitted when the contract receives ETH
     * @param sender The address that sent the ETH
     * @param amount The amount of ETH received in wei
     */
    event EtherReceived(address indexed sender, uint256 amount);
    
    // ============ Errors ============
    
    /**
     * @notice Thrown when a non-owner attempts to call an owner-only function
     */
    error Unauthorized();
    
    /**
     * @notice Thrown when attempting to call a function that is not allowlisted
     * @param target The target contract address
     * @param selector The function selector that was not allowed
     */
    error FunctionNotAllowlisted(address target, bytes4 selector);
    
    /**
     * @notice Thrown when a delegatecall fails
     * @param returnData The return data from the failed delegatecall
     */
    error DelegatecallFailed(bytes returnData);
    
    /**
     * @notice Thrown when an invalid address (zero address) is provided
     */
    error InvalidAddress();
    
    // ============ State Variables ============
    
    /**
     * @notice Returns the address of the wrapped implementation contract
     * @return The immutable address of the wrapped contract
     */
    function wrappedContract() external view returns (address);
    
    /**
     * @notice Returns the current owner address
     * @return The address of the contract owner
     */
    function owner() external view returns (address);
    
    /**
     * @notice Checks if a function selector is allowlisted for a target contract
     * @param target The contract address to check
     * @param selector The function selector to check
     * @return True if the function is allowlisted, false otherwise
     */
    function allowlist(address target, bytes4 selector) external view returns (bool);
    
    // ============ Admin Functions ============
    
    /**
     * @notice Adds a function selector to the allowlist for a target contract
     * @dev MUST be called by the contract owner
     * @dev MUST emit FunctionAllowlisted event on success
     * @dev MUST revert with InvalidAddress if target is zero address
     * @dev MUST revert with Unauthorized if caller is not owner
     * @param target The contract address to allowlist the function for
     * @param selector The 4-byte function selector to allowlist
     */
    function addToAllowlist(address target, bytes4 selector) external;
    
    /**
     * @notice Adds multiple function selectors to the allowlist for a target contract
     * @dev MUST be called by the contract owner
     * @dev MUST emit FunctionAllowlisted event for each selector on success
     * @dev MUST revert with InvalidAddress if target is zero address
     * @dev MUST revert with Unauthorized if caller is not owner
     * @param target The contract address to allowlist the functions for
     * @param selectors Array of 4-byte function selectors to allowlist
     */
    function addBatchToAllowlist(address target, bytes4[] calldata selectors) external;
    
    /**
     * @notice Removes a function selector from the allowlist
     * @dev MUST be called by the contract owner
     * @dev MUST emit FunctionRemovedFromAllowlist event on success
     * @dev MUST revert with Unauthorized if caller is not owner
     * @param target The contract address to remove the function from
     * @param selector The 4-byte function selector to remove
     */
    function removeFromAllowlist(address target, bytes4 selector) external;
    
    /**
     * @notice Transfers ownership of the contract to a new address
     * @dev MUST be called by the current contract owner
     * @dev MUST emit OwnershipTransferred event on success
     * @dev MUST revert with InvalidAddress if newOwner is zero address
     * @dev MUST revert with Unauthorized if caller is not owner
     * @param newOwner The address of the new owner
     */
    function transferOwnership(address newOwner) external;
    
    // ============ Core Functions ============
    
    /**
     * @notice Checks if a function call is allowed for a target contract
     * @param target The target contract address
     * @param selector The function selector to check
     * @return True if the function is allowlisted, false otherwise
     */
    function isAllowed(address target, bytes4 selector) external view returns (bool);
    
    /**
     * @notice Executes a delegatecall to a target contract if the function is allowlisted
     * @dev MUST extract the function selector from the first 4 bytes of data
     * @dev MUST revert with FunctionNotAllowlisted if selector is not allowlisted for target
     * @dev MUST execute delegatecall in the context of this contract
     * @dev MUST emit DelegatecallExecuted event after execution
     * @dev MUST revert with DelegatecallFailed if the delegatecall returns false
     * @dev MUST forward msg.value to the delegatecall
     * @param target The implementation contract to delegatecall
     * @param data The calldata including function selector and arguments (minimum 4 bytes)
     * @return success True if the delegatecall succeeded
     * @return returnData The data returned from the delegatecall
     */
    function executeDelegatecall(address target, bytes calldata data) 
        external 
        payable 
        returns (bool success, bytes memory returnData);
    
    /**
     * @notice Returns the allowlist status for multiple function selectors
     * @param target The contract address to check
     * @param selectors Array of function selectors to check
     * @return statuses Array of boolean values indicating allowlist status for each selector
     */
    function getAllowlistStatus(address target, bytes4[] calldata selectors) 
        external 
        view 
        returns (bool[] memory statuses);
    
    /**
     * @notice Withdraws ETH from the contract to a specified address
     * @dev MUST be called by the contract owner
     * @dev MUST revert with InvalidAddress if recipient is zero address
     * @dev MUST revert with Unauthorized if caller is not owner
     * @dev MUST revert with DelegatecallFailed if the ETH transfer fails
     * @param to The address to send ETH to
     * @param amount The amount of ETH to withdraw in wei
     */
    function withdrawEther(address payable to, uint256 amount) external;
    
    /**
     * @notice Fallback function that intercepts all calls and validates against allowlist
     * @dev MUST extract function selector from msg.sig (first 4 bytes of msg.data)
     * @dev MUST check if selector is allowlisted for wrappedContract
     * @dev MUST revert with FunctionNotAllowlisted if selector is not allowlisted
     * @dev MUST execute delegatecall to wrappedContract with full msg.data
     * @dev MUST forward msg.value to the delegatecall
     * @dev MUST emit DelegatecallExecuted event after execution
     * @dev MUST bubble up revert reasons if delegatecall fails
     * @dev MUST return delegatecall return data if successful
     */
    fallback() external payable;
    
    /**
     * @notice Receive function to accept plain ETH transfers
     * @dev MUST emit EtherReceived event when ETH is received
     */
    receive() external payable;
}
```

## Security Considerations 

- **Storage Collision Risk**: The wrapped contract can overwrite the wrapper's storage (owner, allowlist)
- **Complete Trust Required**: Wrapped contract has full control over wrapper's state
- **Storage Layout Must Match**: If wrapper and implementation use storage, layouts must be compatible




