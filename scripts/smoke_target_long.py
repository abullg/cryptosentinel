#!/usr/bin/env python3
"""Trigger analyze-stream, wait 4 min, check for TARGET/LAB markers."""
import os, sys, paramiko, json, time

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=HOST, port=22, username="root",
          password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30)

# Use a simpler contract — just trigger the static reentrancy finding
# and let the validation pipeline run on it.
TEST_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""

src_json = json.dumps(TEST_CODE)
print("=== Triggering analyze-stream ===", flush=True)
cmd = f"""cat > /tmp/vault.json << 'JSONEOF'
{{"projectId":"test-target-simple","sourceCode":{src_json},"contractName":"SimpleVault","targetType":"contract"}}
JSONEOF
# Run in background, output to file, no hang on this script
nohup bash -c 'curl -sN -X POST http://localhost:3000/api/analyze-stream -H "Content-Type: application/json" -d @/tmp/vault.json --max-time 240' > /tmp/sse_target.txt 2>&1 &
echo "Started PID: $!"
sleep 5
echo "Initial size: $(wc -c < /tmp/sse_target.txt) bytes"
"""
_, o, _ = c.exec_command(cmd, timeout=30)
print(o.read().decode(errors="replace"))

# Wait 3 minutes with periodic checks
print("\n=== Waiting 3 minutes, checking progress every 30s ===", flush=True)
for i in range(6):
    time.sleep(30)
    _, o, _ = c.exec_command("""echo "Check #""" + str(i+1) + """"
echo "Size: $(wc -c < /tmp/sse_target.txt) bytes"
echo "Events: $(grep -c '^event:' /tmp/sse_target.txt 2>/dev/null)"
echo "Findings: $(grep -c '^event: finding' /tmp/sse_target.txt 2>/dev/null)"
echo "Complete: $(grep -c '^event: complete' /tmp/sse_target.txt 2>/dev/null)"
echo "TARGET/LAB markers: $(grep -oE 'TARGET-VALIDATED|LAB-VALIDATED|THEORETICAL' /tmp/sse_target.txt 2>/dev/null | sort | uniq -c | tr '\\n' ' ')"
""", timeout=15)
    print(o.read().decode(errors="replace"), flush=True)

print("\n=== Final full event summary ===", flush=True)
_, o, _ = c.exec_command("""echo "EVENT COUNTS:"
grep '^event:' /tmp/sse_target.txt | sort | uniq -c
echo ""
echo "FINDINGS DETAIL:"
python3 -c "
import json, re
content = open('/tmp/sse_target.txt').read()
findings = re.findall(r'event: finding\\ndata: (\\{.*?\\})\\n\\n', content, re.DOTALL)
print(f'Total findings: {len(findings)}')
for i, f in enumerate(findings, 1):
    try:
        v = json.loads(f).get('vulnerability', {})
        print(f'  #{i} [{v.get(\"severity\",\"?\").upper()}] {v.get(\"title\",\"?\")[:80]}')
        print(f'     confidence: {v.get(\"confidence\",0):.2f}, status: {v.get(\"status\",\"?\")}')
        # Search for TARGET/LAB markers in description
        desc = v.get('description','')
        for marker in ['TARGET-VALIDATED', 'LAB-VALIDATED', 'THEORETICAL', 'TARGET-CONFIRMS', 'TARGET-REFUTES', 'TARGET-PARTIAL']:
            if marker in desc:
                print(f'     [scope marker found]: {marker}')
    except Exception as e:
        print(f'  Parse error: {e}')
"
""", timeout=30)
print(o.read().decode(errors="replace"))

c.close()
print("\n=== DONE ===", flush=True)
