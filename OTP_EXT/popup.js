// Base32 decode (unchanged)
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  let bits = 0, value = 0, output = [];
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
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

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

// chrome.storage helpers
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
function getAddCollapsed() {
  return new Promise(res =>
    chrome.storage.local.get({ addCollapsed: false }, data => res(data.addCollapsed))
  );
}
function saveAddCollapsed(val) {
  return new Promise(res =>
    chrome.storage.local.set({ addCollapsed: val }, () => res())
  );
}

const addHeader     = document.getElementById("add-header");
const toggleIcon    = document.getElementById("toggle-icon");
const addContainer  = document.getElementById("add-container");
const form          = document.getElementById("add-form");
const labelInput    = document.getElementById("label-input");
const secretInput   = document.getElementById("secret-input");
const otpListEl     = document.getElementById("otp-list");
const countdownEl   = document.getElementById("countdown");

let entries = [];

// Initialize collapsed state on load
(async function restoreCollapsedState() {
  const collapsed = await getAddCollapsed();
  if (collapsed) {
    addContainer.classList.add("hidden");
    toggleIcon.textContent = "►";
  } else {
    addContainer.classList.remove("hidden");
    toggleIcon.textContent = "▼";
  }
})();

// Toggle collapse/expand and persist
addHeader.addEventListener("click", async () => {
  const hidden = addContainer.classList.toggle("hidden");
  toggleIcon.textContent = hidden ? "►" : "▼";
  await saveAddCollapsed(hidden);
});

// Build list, generate codes immediately, wire delete + copy
async function initUI() {
  const secrets = await getSecrets();
  entries = [];
  otpListEl.innerHTML = "";

  secrets.forEach(({ label, secret }, idx) => {
    const entryEl = document.createElement("div");
    entryEl.className = "otp-entry";

    const lbl = document.createElement("span");
    lbl.className = "otp-label";
    lbl.textContent = label;

    const cd = document.createElement("span");
    cd.className = "otp-code";

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "delete-btn";
    deleteBtn.textContent = "✕";
    deleteBtn.title = "Delete this OTP";
    deleteBtn.addEventListener("click", async e => {
      e.stopPropagation();
      const all = await getSecrets();
      all.splice(idx, 1);
      await saveSecrets(all);
      await initUI();
    });

    entryEl.addEventListener("click", async () => {
      const code = cd.textContent;
      try {
        await navigator.clipboard.writeText(code);
        const fb = document.createElement("span");
        fb.className = "copy-feedback";
        fb.textContent = "Copied!";
        entryEl.appendChild(fb);
        setTimeout(() => fb.remove(), 1000);
      } catch (err) {
        console.error("Copy failed", err);
      }
    });

    entryEl.append(lbl, cd, deleteBtn);
    otpListEl.appendChild(entryEl);
    entries.push({ secret, codeEl: cd });
  });

  // Immediately generate and display each code
  await Promise.all(entries.map(async ({ secret, codeEl }) => {
    codeEl.textContent = await generateTOTP(secret);
  }));
}

// Refresh countdown & regenerate only on the 30s mark
async function tick() {
  const now = Math.floor(Date.now() / 1000);
  const secs = now % 30;
  countdownEl.textContent = `${30 - secs}s until refresh`;
  if (secs === 0) {
    for (const { secret, codeEl } of entries) {
      codeEl.textContent = await generateTOTP(secret);
    }
  }
}

// Handle new OTP submissions
form.addEventListener("submit", async e => {
  e.preventDefault();
  const label  = labelInput.value.trim();
  const secret = secretInput.value.trim().replace(/\s+/g, "");
  if (!label || !secret) return;
  const all = await getSecrets();
  all.push({ label, secret });
  await saveSecrets(all);
  labelInput.value = "";
  secretInput.value = "";
  await initUI();
});

// Initial render + start ticker
initUI().then(() => {
  tick();
  setInterval(tick, 1000);
});