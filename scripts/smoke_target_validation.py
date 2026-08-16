#!/usr/bin/env python3
"""Smoke-test the new TARGET validation by triggering /api/validate-vuln
with a contract that has an address in source code."""
import os, sys, paramiko, json, time

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=HOST, port=22, username="root",
          password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30)

# Create a Solidity contract with an access_control vuln AND a real
# mainnet address (USDT — owner is 0xC09...BinanceHotWallet which is an EOA).
# We embed the address in source so activelyValidate picks it up.
TEST_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Reference: TetherToken on Ethereum mainnet at 0xdAC17F958D2ee523a2206206994597C13D831ec7
contract SimpleVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable: anyone can call withdraw, no access control
    function withdraw(uint256 amount) external {
        // No require(msg.sender == owner)
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        // State update AFTER external call — reentrancy
        balances[msg.sender] -= amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""

# First, insert a vulnerability with an address in the description via
# direct SQL or via the API. Easier: use the analyze-stream endpoint with
# the source code embedded.
print("=== Step 1: Pre-flight check /api/settings ===")
_, o, _ = c.exec_command("curl -s http://localhost:3000/api/settings | head -c 200", timeout=15)
print(o.read().decode(errors="replace")[:200])

print("\n=== Step 2: Run /api/analyze-stream with the vulnerable vault ===")
print("(contract embeds USDT mainnet address 0xdAC17... for target validation)")

# Write source code to a file on the VPS for curl -d @file
src_json = json.dumps(TEST_CODE)
# Send the analyze request and stream SSE for up to 3 minutes
cmd = f"""cd /tmp && cat > /tmp/vault.json << 'JSONEOF'
{{"projectId":"test-target-val","sourceCode":{src_json},"contractName":"SimpleVault","targetType":"contract"}}
JSONOF
curl -sN -X POST http://localhost:3000/api/analyze-stream -H "Content-Type: application/json" -d @/tmp/vault.json --max-time 180 2>&1 | grep -E "^(event:|data:.*(TARGET|LAB|THEORETICAL|confirmed|validationScope))" | head -60
"""
# Simpler: just dump all output to a file, then grep
cmd = f"""cd /tmp && cat > /tmp/vault.json << 'JSONEOF'
{{"projectId":"test-target-val","sourceCode":{src_json},"contractName":"SimpleVault","targetType":"contract"}}
JSONEOF
curl -sN -X POST http://localhost:3000/api/analyze-stream -H "Content-Type: application/json" -d @/tmp/vault.json --max-time 180 > /tmp/sse_out.txt 2>&1
echo "OUTPUT SIZE: $(wc -c < /tmp/sse_out.txt)"
echo "---EVENT COUNTS---"
grep "^event:" /tmp/sse_out.txt | sort | uniq -c
echo "---FINDINGS---"
grep -E '"title"|"severity"|"confidence"|"validationScope"|"status"' /tmp/sse_out.txt | head -40
echo "---TARGET-VALIDATED or LAB-VALIDATED markers---"
grep -oE "TARGET-VALIDATED[^\"\\\\]*|LAB-VALIDATED[^\"\\\\]*|THEORETICAL[^\"\\\\]*" /tmp/sse_out.txt | head -20
"""

print("Running (up to 3 minutes)...", flush=True)
_, o, e = c.exec_command(cmd, timeout=240)
print(o.read().decode(errors="replace"))
err = e.read().decode(errors="replace")
if err: print("STDERR:", err[:500])

c.close()
print("\n=== DONE ===", flush=True)
