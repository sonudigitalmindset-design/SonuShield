// Memory-hard proof-of-work solver: Argon2id in pure JavaScript.
//
// This file is embedded into the Stage 2 memory-hard challenge page
// (see memorypow.go). It has no dependencies: no WASM, no CDN, no
// WebCrypto. The implementation follows RFC 9106 (Argon2) and
// RFC 7693 (Blake2b) and is verified against Go's
// golang.org/x/crypto/argon2 output with test vectors (see the
// Batch 6 notes); any change here must re-run that comparison.
//
// 64-bit words are pairs of signed 32-bit limbs (hi, lo) so the
// arithmetic stays exact in doubles and fast without BigInt on
// the hot path. BigInt is used only for one cold indexing
// computation (J1 squared, shifted) where double precision
// would not be exact.
//
// Placeholders replaced by the server at serve time:
// __ARGON_SALT_HEX__, __ARGON_BITS__, __ARGON_MEMORY_KB__,
// __ARGON_TIME__. Under node (no document) the solver does not
// auto-start and the core functions are exported for testing.
(function () {
'use strict';

// ---- Blake2b (RFC 7693), one-shot, variable output length ----

var IV_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
var IV_L = [0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
            0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179];

var SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
];

// G mixes four words of the working vector with two message words.
// vH/vL hold 16 words as (hi, lo) limb pairs.
function blakeG(vH, vL, a, b, c, d, xh, xl, yh, yl) {
  var s, carry, th, tl;
  // a = a + b + x
  s = (vL[a] >>> 0) + (vL[b] >>> 0) + (xl >>> 0);
  carry = Math.floor(s / 4294967296);
  vL[a] = (s - carry * 4294967296) | 0;
  vH[a] = (vH[a] + vH[b] + xh + carry) | 0;
  // d = rotr(d ^ a, 32)
  th = vH[d] ^ vH[a]; tl = vL[d] ^ vL[a];
  vH[d] = tl; vL[d] = th;
  // c = c + d
  s = (vL[c] >>> 0) + (vL[d] >>> 0);
  carry = Math.floor(s / 4294967296);
  vL[c] = (s - carry * 4294967296) | 0;
  vH[c] = (vH[c] + vH[d] + carry) | 0;
  // b = rotr(b ^ c, 24)
  th = vH[b] ^ vH[c]; tl = vL[b] ^ vL[c];
  vH[b] = ((th >>> 24) | (tl << 8)) | 0;
  vL[b] = ((tl >>> 24) | (th << 8)) | 0;
  // a = a + b + y
  s = (vL[a] >>> 0) + (vL[b] >>> 0) + (yl >>> 0);
  carry = Math.floor(s / 4294967296);
  vL[a] = (s - carry * 4294967296) | 0;
  vH[a] = (vH[a] + vH[b] + yh + carry) | 0;
  // d = rotr(d ^ a, 16)
  th = vH[d] ^ vH[a]; tl = vL[d] ^ vL[a];
  vH[d] = ((th >>> 16) | (tl << 16)) | 0;
  vL[d] = ((tl >>> 16) | (th << 16)) | 0;
  // c = c + d
  s = (vL[c] >>> 0) + (vL[d] >>> 0);
  carry = Math.floor(s / 4294967296);
  vL[c] = (s - carry * 4294967296) | 0;
  vH[c] = (vH[c] + vH[d] + carry) | 0;
  // b = rotr(b ^ c, 63)
  th = vH[b] ^ vH[c]; tl = vL[b] ^ vL[c];
  vH[b] = ((th << 1) | (tl >>> 31)) | 0;
  vL[b] = ((tl << 1) | (th >>> 31)) | 0;
}

function blake2bCompress(hH, hL, mH, mL, counter, isLast) {
  var vH = new Array(16), vL = new Array(16);
  var i;
  for (i = 0; i < 8; i++) { vH[i] = hH[i]; vL[i] = hL[i]; }
  for (i = 0; i < 8; i++) { vH[8 + i] = IV_H[i]; vL[8 + i] = IV_L[i]; }
  vL[12] ^= counter & 0xffffffff;
  vH[12] ^= Math.floor(counter / 4294967296);
  if (isLast) { vH[14] ^= 0xffffffff; vL[14] ^= 0xffffffff; }
  for (var r = 0; r < 12; r++) {
    var s = SIGMA[r];
    blakeG(vH, vL, 0, 4, 8, 12, mH[s[0]], mL[s[0]], mH[s[1]], mL[s[1]]);
    blakeG(vH, vL, 1, 5, 9, 13, mH[s[2]], mL[s[2]], mH[s[3]], mL[s[3]]);
    blakeG(vH, vL, 2, 6, 10, 14, mH[s[4]], mL[s[4]], mH[s[5]], mL[s[5]]);
    blakeG(vH, vL, 3, 7, 11, 15, mH[s[6]], mL[s[6]], mH[s[7]], mL[s[7]]);
    blakeG(vH, vL, 0, 5, 10, 15, mH[s[8]], mL[s[8]], mH[s[9]], mL[s[9]]);
    blakeG(vH, vL, 1, 6, 11, 12, mH[s[10]], mL[s[10]], mH[s[11]], mL[s[11]]);
    blakeG(vH, vL, 2, 7, 8, 13, mH[s[12]], mL[s[12]], mH[s[13]], mL[s[13]]);
    blakeG(vH, vL, 3, 4, 9, 14, mH[s[14]], mL[s[14]], mH[s[15]], mL[s[15]]);
  }
  for (i = 0; i < 8; i++) {
    hH[i] ^= vH[i] ^ vH[i + 8];
    hL[i] ^= vL[i] ^ vL[i + 8];
  }
}

// blake2b returns outLen bytes (1..64) of the unkeyed hash of data.
function blake2b(outLen, data) {
  var hH = IV_H.slice(), hL = IV_L.slice();
  // Parameter word 0: digest_length | key_length<<8 | fanout<<16 |
  // depth<<24 occupies the LOW 32 bits; leaf_length (0) the high.
  hL[0] ^= 0x01010000 ^ outLen;
  var mH = new Array(16), mL = new Array(16);
  var offset = 0, remaining = data.length;
  function loadBlock(off, len) {
    var block = new Uint8Array(128);
    block.set(data.subarray(off, off + len));
    for (var i = 0; i < 16; i++) {
      var o = i * 8;
      mL[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) | 0;
      mH[i] = (block[o + 4] | (block[o + 5] << 8) | (block[o + 6] << 16) | (block[o + 7] << 24)) | 0;
    }
  }
  if (remaining === 0) {
    loadBlock(0, 0);
    blake2bCompress(hH, hL, mH, mL, 0, true);
  } else {
    while (remaining > 128) {
      loadBlock(offset, 128);
      blake2bCompress(hH, hL, mH, mL, offset + 128, false);
      offset += 128;
      remaining -= 128;
    }
    loadBlock(offset, remaining);
    blake2bCompress(hH, hL, mH, mL, data.length, true);
  }
  var out = new Uint8Array(outLen);
  for (var i = 0; i < outLen; i++) {
    var w = i >> 3, b = i & 7;
    var word = b < 4 ? hL[w] : hH[w];
    out[i] = (word >>> ((b & 3) * 8)) & 0xff;
  }
  return out;
}

// ---- Argon2id (RFC 9106), single lane, no secret, no AD ----

// H' variable-length hash: outLen bytes from input.
function hashH(outLen, input) {
  if (outLen <= 64) {
    var prefixed = new Uint8Array(4 + input.length);
    prefixed[0] = outLen & 0xff;
    prefixed[1] = (outLen >> 8) & 0xff;
    prefixed[2] = (outLen >> 16) & 0xff;
    prefixed[3] = (outLen >> 24) & 0xff;
    prefixed.set(input, 4);
    return blake2b(outLen, prefixed);
  }
  var r = Math.ceil(outLen / 32) - 2;
  var out = new Uint8Array(outLen);
  // The first block hashes LE32(outLen) || input.
  var prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >> 8) & 0xff;
  prefixed[2] = (outLen >> 16) & 0xff;
  prefixed[3] = (outLen >> 24) & 0xff;
  prefixed.set(input, 4);
  var v = blake2b(64, prefixed);
  out.set(v.subarray(0, 32), 0);
  var pos = 32;
  for (var i = 1; i < r; i++) {
    v = blake2b(64, v);
    out.set(v.subarray(0, 32), pos);
    pos += 32;
  }
  v = blake2b(outLen - 32 * r, v);
  out.set(v, pos);
  return out;
}

// fBlaMka: x + y + 2*(x mod 2^32)*(y mod 2^32), on (hi, lo) limbs.
// Returns [hi, lo].
function fBlaMka(xh, xl, yh, yl) {
  var x0 = xl & 0xffff, x1 = (xl >>> 16) & 0xffff;
  var y0 = yl & 0xffff, y1 = (yl >>> 16) & 0xffff;
  var p0 = x0 * y0;
  var p1 = x0 * y1 + x1 * y0;
  var p2 = x1 * y1;
  var lo = p0 + (p1 & 0xffff) * 65536;
  var carry = Math.floor(lo / 4294967296);
  lo = lo - carry * 4294967296;
  var hi = p2 + Math.floor(p1 / 65536) + carry;
  // Multiply the 64-bit product by 2.
  var hi2 = (hi * 2 + Math.floor(lo / 2147483648)) % 4294967296;
  var lo2 = (lo * 2) % 4294967296;
  // x + y + 2*product.
  var s = (xl >>> 0) + (yl >>> 0) + lo2;
  carry = Math.floor(s / 4294967296);
  var rlo = (s - carry * 4294967296) | 0;
  var rhi = (xh + yh + hi2 + carry) | 0;
  return [rhi, rlo];
}

// Argon2 G on four words of a 16-word window (wH/wL arrays of 16).
function argonG(wH, wL, a, b, c, d) {
  var t, th, tl;
  t = fBlaMka(wH[a], wL[a], wH[b], wL[b]);
  wH[a] = t[0]; wL[a] = t[1];
  th = wH[d] ^ wH[a]; tl = wL[d] ^ wL[a];
  wH[d] = tl; wL[d] = th;
  t = fBlaMka(wH[c], wL[c], wH[d], wL[d]);
  wH[c] = t[0]; wL[c] = t[1];
  th = wH[b] ^ wH[c]; tl = wL[b] ^ wL[c];
  wH[b] = ((th >>> 24) | (tl << 8)) | 0;
  wL[b] = ((tl >>> 24) | (th << 8)) | 0;
  t = fBlaMka(wH[a], wL[a], wH[b], wL[b]);
  wH[a] = t[0]; wL[a] = t[1];
  th = wH[d] ^ wH[a]; tl = wL[d] ^ wL[a];
  wH[d] = ((th >>> 16) | (tl << 16)) | 0;
  wL[d] = ((tl >>> 16) | (th << 16)) | 0;
  t = fBlaMka(wH[c], wL[c], wH[d], wL[d]);
  wH[c] = t[0]; wL[c] = t[1];
  th = wH[b] ^ wH[c]; tl = wL[b] ^ wL[c];
  wH[b] = ((th << 1) | (tl >>> 31)) | 0;
  wL[b] = ((tl << 1) | (th >>> 31)) | 0;
}

// P: one Blake2b-style round over 16 words (no message input).
function argonP(wH, wL) {
  argonG(wH, wL, 0, 4, 8, 12);
  argonG(wH, wL, 1, 5, 9, 13);
  argonG(wH, wL, 2, 6, 10, 14);
  argonG(wH, wL, 3, 7, 11, 15);
  argonG(wH, wL, 0, 5, 10, 15);
  argonG(wH, wL, 1, 6, 11, 12);
  argonG(wH, wL, 2, 7, 8, 13);
  argonG(wH, wL, 3, 4, 9, 14);
}

// Block compression: out = R(X xor Y) xor (X xor Y), where R
// applies P to the 8 rows then the 8 columns of the 128-word
// block. Blocks are (hi, lo) limb arrays of length 128.
function blockCompress(outH, outL, xH, xL, yH, yL) {
  var zH = new Array(128), zL = new Array(128);
  var rH = new Array(128), rL = new Array(128);
  var i, j;
  for (i = 0; i < 128; i++) {
    zH[i] = xH[i] ^ yH[i];
    zL[i] = xL[i] ^ yL[i];
    rH[i] = zH[i];
    rL[i] = zL[i];
  }
  // Rows: 8 groups of 16 consecutive words.
  for (i = 0; i < 8; i++) {
    var wH = rH.slice(i * 16, i * 16 + 16);
    var wL = rL.slice(i * 16, i * 16 + 16);
    argonP(wH, wL);
    for (j = 0; j < 16; j++) { rH[i * 16 + j] = wH[j]; rL[i * 16 + j] = wL[j]; }
  }
  // Columns: 8 groups striding 16 words.
  for (i = 0; i < 8; i++) {
    var cH = new Array(16), cL = new Array(16);
    for (j = 0; j < 8; j++) {
      cH[2 * j] = rH[j * 16 + 2 * i];
      cL[2 * j] = rL[j * 16 + 2 * i];
      cH[2 * j + 1] = rH[j * 16 + 2 * i + 1];
      cL[2 * j + 1] = rL[j * 16 + 2 * i + 1];
    }
    argonP(cH, cL);
    for (j = 0; j < 8; j++) {
      rH[j * 16 + 2 * i] = cH[2 * j];
      rL[j * 16 + 2 * i] = cL[2 * j];
      rH[j * 16 + 2 * i + 1] = cH[2 * j + 1];
      rL[j * 16 + 2 * i + 1] = cL[2 * j + 1];
    }
  }
  for (i = 0; i < 128; i++) {
    outH[i] = zH[i] ^ rH[i];
    outL[i] = zL[i] ^ rL[i];
  }
}

function le32(n) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

function blockFromBytes(bytes) {
  var h = new Array(128), l = new Array(128);
  for (var i = 0; i < 128; i++) {
    var o = i * 8;
    l[i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) | 0;
    h[i] = (bytes[o + 4] | (bytes[o + 5] << 8) | (bytes[o + 6] << 16) | (bytes[o + 7] << 24)) | 0;
  }
  return [h, l];
}

function blockToBytes(h, l) {
  var out = new Uint8Array(1024);
  for (var i = 0; i < 128; i++) {
    var o = i * 8;
    out[o] = l[i] & 0xff; out[o + 1] = (l[i] >> 8) & 0xff;
    out[o + 2] = (l[i] >> 16) & 0xff; out[o + 3] = (l[i] >> 24) & 0xff;
    out[o + 4] = h[i] & 0xff; out[o + 5] = (h[i] >> 8) & 0xff;
    out[o + 6] = (h[i] >> 16) & 0xff; out[o + 7] = (h[i] >> 24) & 0xff;
  }
  return out;
}

// argon2id returns 32 bytes. password/salt are Uint8Arrays,
// time is the pass count, memoryKB the memory size in KiB.
function argon2id(password, salt, time, memoryKB) {
  var outLen = 32;
  // H0 = Blake2b-64 over the parameter block.
  var h0input = [];
  function push32(n) { var b = le32(n); for (var i = 0; i < 4; i++) h0input.push(b[i]); }
  push32(1); // lanes
  push32(outLen);
  push32(memoryKB);
  push32(time);
  push32(0x13); // version
  push32(2); // Argon2id
  push32(password.length);
  for (var i = 0; i < password.length; i++) h0input.push(password[i]);
  push32(salt.length);
  for (i = 0; i < salt.length; i++) h0input.push(salt[i]);
  push32(0); // secret length
  push32(0); // AD length
  var h0 = blake2b(64, new Uint8Array(h0input));

  var memBlocks = 4 * Math.floor(memoryKB / 4);
  var laneLen = memBlocks;
  var segLen = memBlocks / 4;

  var memH = new Int32Array(memBlocks * 128);
  var memL = new Int32Array(memBlocks * 128);

  function blockAt(idx) {
    return [memH.subarray(idx * 128, idx * 128 + 128),
            memL.subarray(idx * 128, idx * 128 + 128)];
  }
  function setBlock(idx, h, l) {
    memH.set(h, idx * 128);
    memL.set(l, idx * 128);
  }

  // First two blocks from H'.
  for (var b = 0; b < 2; b++) {
    var inp = new Uint8Array(72);
    inp.set(h0, 0);
    var lb = le32(b); for (i = 0; i < 4; i++) inp[64 + i] = lb[i];
    var bl = blockFromBytes(hashH(1024, inp));
    setBlock(b, bl[0], bl[1]);
  }

  var zeroH = new Array(128).fill(0), zeroL = new Array(128).fill(0);
  var tmpH = new Array(128), tmpL = new Array(128);
  var addrH = new Array(128), addrL = new Array(128);
  var inH = new Array(128), inL = new Array(128);

  for (var pass = 0; pass < time; pass++) {
    for (var slice = 0; slice < 4; slice++) {
      var independent = (pass === 0 && slice < 2);
      // Address-block state for data-independent addressing.
      for (i = 0; i < 128; i++) { inH[i] = 0; inL[i] = 0; addrH[i] = 0; addrL[i] = 0; }
      inL[0] = pass; inL[1] = 0; inL[2] = slice;
      inL[3] = memBlocks; inL[4] = time; inL[5] = 2;
      var addrCounter = 0;
      function nextAddresses() {
        addrCounter++;
        inL[6] = addrCounter;
        blockCompress(tmpH, tmpL, zeroH, zeroL, inH, inL);
        blockCompress(addrH, addrL, zeroH, zeroL, tmpH, tmpL);
      }
      var startIndex = 0;
      if (pass === 0 && slice === 0) {
        startIndex = 2;
        if (independent) { nextAddresses(); }
      }
      for (var index = startIndex; index < segLen; index++) {
        var curOff = slice * segLen + index;
        var prevOff = curOff === 0 ? laneLen - 1 : curOff - 1;
        var pseudoRandLo, pseudoRandHi;
        if (independent) {
          if (index % 128 === 0) { nextAddresses(); }
          pseudoRandHi = addrH[index % 128];
          pseudoRandLo = addrL[index % 128];
        } else {
          pseudoRandHi = memH[prevOff * 128];
          pseudoRandLo = memL[prevOff * 128];
        }
        // Reference position (single lane: same lane always).
        var refArea;
        if (pass === 0) {
          refArea = slice === 0 ? index - 1 : slice * segLen + index - 1;
        } else {
          refArea = laneLen - segLen + index - 1;
        }
        var j1 = pseudoRandLo >>> 0;
        var rel = Number((BigInt(j1) * BigInt(j1)) >> 32n);
        rel = refArea - 1 - Math.floor((refArea * rel) / 4294967296);
        var startPos = pass === 0 ? 0 : (slice === 3 ? 0 : (slice + 1) * segLen);
        var refOff = (startPos + rel) % laneLen;

        var prev = blockAt(prevOff);
        var ref = blockAt(refOff);
        var outH = new Array(128), outL = new Array(128);
        blockCompress(outH, outL,
          Array.prototype.slice.call(prev[0]), Array.prototype.slice.call(prev[1]),
          Array.prototype.slice.call(ref[0]), Array.prototype.slice.call(ref[1]));
        if (pass > 0) {
          var cur = blockAt(curOff);
          for (i = 0; i < 128; i++) {
            outH[i] ^= cur[0][i];
            outL[i] ^= cur[1][i];
          }
        }
        setBlock(curOff, outH, outL);
      }
    }
  }

  var last = blockAt(laneLen - 1);
  var finalBytes = blockToBytes(
    Array.prototype.slice.call(last[0]), Array.prototype.slice.call(last[1]));
  return hashH(outLen, finalBytes);
}

function hexToBytes(hex) {
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function hasLeadingZeroBits(bytes, bits) {
  var full = Math.floor(bits / 8);
  for (var i = 0; i < full; i++) {
    if (bytes[i] !== 0) { return false; }
  }
  var rem = bits % 8;
  if (rem === 0) { return true; }
  return (bytes[full] >> (8 - rem)) === 0;
}

var api = {
  blake2b: blake2b,
  hashH: hashH,
  argon2id: argon2id,
  hexToBytes: hexToBytes,
  hasLeadingZeroBits: hasLeadingZeroBits
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = api;
}

// ---- Solver (browser only) ----

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  (function () {
    var saltHex = '__ARGON_SALT_HEX__';
    var bits = parseInt('__ARGON_BITS__', 10);
    var memoryKB = parseInt('__ARGON_MEMORY_KB__', 10);
    var timeCost = parseInt('__ARGON_TIME__', 10);
    var salt = hexToBytes(saltHex);
    var status = document.getElementById('mpow-status');
    var counter = 0;
    var encoder = new TextEncoder();
    function attempt() {
      var password = encoder.encode(saltHex + ':' + counter);
      var out = argon2id(password, salt, timeCost, memoryKB);
      if (hasLeadingZeroBits(out, bits)) {
        document.getElementById('mpow-solution').value = String(counter);
        document.getElementById('mpow-form').submit();
        return;
      }
      counter++;
      if (status && counter % 4 === 0) {
        status.textContent = 'Working… attempt ' + counter;
      }
      // Yield so the page stays responsive.
      setTimeout(attempt, 0);
    }
    setTimeout(attempt, 0);
  })();
}

})();
