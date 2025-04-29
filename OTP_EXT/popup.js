// Your Base32-encoded shared secret
const TOTP_SHARED_SECRET = "GIO32ZTF6KSJKNBG";

// 1) Base32 decode
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

// 2) Generate a TOTP code
async function generateTOTP(secret) {
  const keyBytes = base32Decode(secret);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30);

  // 8-byte big‐endian counter
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // high bits (will be zero for time < 2^32*30)
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);

  // import key & compute HMAC-SHA1
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const hmac = await crypto.subtle.sign("HMAC", cryptoKey, buf);
  const hash = new Uint8Array(hmac);

  const offset = hash[hash.length - 1] & 0x0F;
  const binary =
    ((hash[offset]   & 0x7F) << 24) |
    ((hash[offset+1] & 0xFF) << 16) |
    ((hash[offset+2] & 0xFF) <<  8) |
    ((hash[offset+3] & 0xFF)      );

  const otp = (binary % 1_000_000).toString().padStart(6, "0");
  return otp;
}

// 3) Update UI every second
async function update() {
  const codeEl      = document.getElementById("code");
  const countdownEl = document.getElementById("countdown");
  const now = Math.floor(Date.now() / 1000);
  const secs = now % 30;
  const left = 30 - secs;

  codeEl.textContent      = await generateTOTP(TOTP_SHARED_SECRET);
  countdownEl.textContent = `${left}s until refresh`;
}

// on load…
update();
setInterval(update, 1000);