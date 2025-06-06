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
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
    );
    const hmac = await crypto.subtle.sign("HMAC", cryptoKey, buf);
    const hash = new Uint8Array(hmac);
    const offset = hash[hash.length - 1] & 0x0F;
    const binary =
        ((hash[offset] & 0x7F) << 24) |
        ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) |
        (hash[offset + 3] & 0xFF);
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
        chrome.storage.local.get({ addCollapsed: false }, data =>
            res(data.addCollapsed)
        )
    );
}
function saveAddCollapsed(val) {
    return new Promise(res =>
        chrome.storage.local.set({ addCollapsed: val }, () => res())
    );
}

const addHeader = document.getElementById("add-header");
const toggleIcon = document.getElementById("toggle-icon");
const addContainer = document.getElementById("add-container");
const form = document.getElementById("add-form");
const labelInput = document.getElementById("label-input");
const secretInput = document.getElementById("secret-input");
const otpListEl = document.getElementById("otp-list");
const countdownEl = document.getElementById("countdown");

let entries = [];
let dragSrcIndex = null;

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

// Build list, generate codes, wire delete/copy/rename/drag
async function initUI() {
    const secrets = await getSecrets();
    entries = [];
    otpListEl.innerHTML = "";

    secrets.forEach(({ label, secret }, idx) => {
        const entryEl = document.createElement("div");
        entryEl.className = "otp-entry";
        entryEl.draggable = true;
        entryEl.dataset.index = idx;

        // DRAG & DROP EVENTS
        entryEl.addEventListener("dragstart", e => {
            dragSrcIndex = idx;
            e.dataTransfer.effectAllowed = "move";
        });

        entryEl.addEventListener("dragover", e => {
            e.preventDefault();
            entryEl.classList.add("drag-over");
            e.dataTransfer.dropEffect = "move";
        });

        entryEl.addEventListener("dragleave", () => {
            entryEl.classList.remove("drag-over");
        });

        entryEl.addEventListener("drop", async e => {
            e.preventDefault();
            entryEl.classList.remove("drag-over");
            const destIndex = parseInt(entryEl.dataset.index, 10);
            if (dragSrcIndex === null || destIndex === dragSrcIndex) return;

            const all = await getSecrets();
            const movedItem = all.splice(dragSrcIndex, 1)[0];
            all.splice(destIndex, 0, movedItem);
            await saveSecrets(all);
            await initUI();
        });

        // LABEL
        const lbl = document.createElement("span");
        lbl.className = "otp-label";
        lbl.textContent = label;

        // CODE FIELD
        const cd = document.createElement("span");
        cd.className = "otp-code";

        // RENAME BUTTON (✎)
        const renameBtn = document.createElement("button");
        renameBtn.className = "rename-btn";
        renameBtn.textContent = "✎";
        renameBtn.title = "Rename this OTP";
        renameBtn.addEventListener("click", async e => {
            e.stopPropagation();
            const wantRename = confirm(
                `Are you sure you want to rename “${label}”?`
            );
            if (!wantRename) return;

            const newLabel = prompt("Enter the new label:", label);
            if (newLabel && newLabel.trim() !== "") {
                const all = await getSecrets();
                all[idx].label = newLabel.trim();
                await saveSecrets(all);
                await initUI();
            }
        });

        // DELETE BUTTON (✕)
        const deleteBtn = document.createElement("button");
        deleteBtn.className = "delete-btn";
        deleteBtn.textContent = "✕";
        deleteBtn.title = "Delete this OTP";
        deleteBtn.addEventListener("click", async e => {
            e.stopPropagation();
            const wantDelete = confirm(
                `Are you sure you want to delete “${label}”?`
            );
            if (!wantDelete) return;

            const all = await getSecrets();
            all.splice(idx, 1);
            await saveSecrets(all);
            await initUI();
        });

        // COPY ON CLICK
        entryEl.addEventListener("click", async () => {
            const code = cd.textContent;
            try {
                await navigator.clipboard.writeText(code);

                // ── change is here ──────────────────────────────────────────────────
                // Instead of appending to entryEl, insert feedback inside the code span:
                const fb = document.createElement("span");
                fb.className = "copy-feedback";
                fb.textContent = "Copied!";
                cd.appendChild(fb);

                setTimeout(() => {
                    fb.remove();
                }, 1000);
                // ────────────────────────────────────────────────────────────────────

            } catch (err) {
                console.error("Copy failed", err);
            }
        });

        // ─── ORDER OF ELEMENTS ─────────────────────────────────────────────────
        // label | code (with inline feedback) | rename | delete
        entryEl.append(lbl, cd, renameBtn, deleteBtn);
        otpListEl.appendChild(entryEl);
        entries.push({ secret, codeEl: cd });
    });

    // Generate and display each code immediately
    await Promise.all(
        entries.map(async ({ secret, codeEl }) => {
            codeEl.textContent = await generateTOTP(secret);
        })
    );
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
    const label = labelInput.value.trim();
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
    tick().catch(console.error);
    setInterval(() => {
        tick().catch(console.error);
    }, 1000);
});
