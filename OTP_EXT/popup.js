// Base32 decode
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  let bits = 0, value = 0;
  const output = [];
  input = input.replace(/=+$/, "").toUpperCase();
  for (const char of input) {
    const idx = BASE32_CHARS.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >>> bits) & 0xFF);
    }
  }
  return new Uint8Array(output);
}

async function generateTOTP(secret) {
  const keyBytes = base32Decode(secret);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30);

  // 8-byte big‐endian counter
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  // HMAC-SHA1
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" },
    false, ["sign"]
  );
  const hmac = await crypto.subtle.sign("HMAC", cryptoKey, buf);
  const hash = new Uint8Array(hmac);

  const offset = hash[hash.length - 1] & 0x0F;
  const binary =
    ((hash[offset]   & 0x7F) << 24) |
    ((hash[offset+1] & 0xFF) << 16) |
    ((hash[offset+2] & 0xFF) <<  8) |
    ( hash[offset+3] & 0xFF );

  return (binary % 1_000_000).toString().padStart(6, "0");
}

// Load and save our list of secrets in chrome.storage
function getSecrets() {
  return new Promise(res =>
    chrome.storage.local.get({ secrets: [] }, data => res(data.secrets))
  );
}
function saveSecrets(secrets) {
  return new Promise(res =>
    chrome.storage.local.set({ secrets }, () => res())
  );
}

const otpListEl = document.getElementById("otp-list");
const countdownEl = document.getElementById("countdown");
const form = document.getElementById("add-form");
const labelInput = document.getElementById("label-input");
const secretInput = document.getElementById("secret-input");

// Render all codes
async function updateUI() {
  const secrets = await getSecrets();
  otpListEl.innerHTML = "";

  const now = Math.floor(Date.now() / 1000);
  const secs = now % 30;
  const left = 30 - secs;
  countdownEl.textContent = `${left}s until refresh`;

  for (const { label, secret } of secrets) {
    const code = await generateTOTP(secret);

    const entry = document.createElement("div");
    entry.className = "otp-entry";

    const lbl = document.createElement("span");
    lbl.className = "otp-label";
    lbl.textContent = label;

    const cd = document.createElement("span");
    cd.className = "otp-code";
    cd.textContent = code;
    cd.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(code);
        const fb = document.createElement("span");
        fb.className = "copy-feedback";
        fb.textContent = "Copied!";
        entry.appendChild(fb);
        setTimeout(() => fb.remove(), 1000);
      } catch (e) {
        console.error("Copy failed", e);
      }
    });

    entry.append(lbl, cd);
    otpListEl.appendChild(entry);
  }
}

// Periodic refresh
updateUI();
setInterval(updateUI, 1000);

// Handle new secret submissions
form.addEventListener("submit", async e => {
  e.preventDefault();
  const label = labelInput.value.trim();
  const secret = secretInput.value.trim().replace(/\s+/g, "");
  if (!label || !secret) return;

  const secrets = await getSecrets();
  secrets.push({ label, secret });
  await saveSecrets(secrets);

  labelInput.value = "";
  secretInput.value = "";
  updateUI();
});