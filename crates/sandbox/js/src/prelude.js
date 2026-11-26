// The prelude of the JavaScript library module: evaluated before the script, in the same
// realm. It takes away what would make a run depend on anything but its inputs (the clock and
// Math.random), and adds the few web APIs signing scripts use that ECMAScript lacks:
// TextEncoder and TextDecoder (UTF-8 only), atob and btoa.
(function (g) {
  "use strict";

  // No clock and no randomness: a script gets the time and random bytes from its inputs.
  delete g.Date;
  delete g.Math.random;

  function encode(input) {
    const s = String(input);
    const out = [];
    for (let i = 0; i < s.length; i++) {
      let c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
        const d = s.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) {
          c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
          i++;
        } else {
          c = 0xfffd;
        }
      } else if (c >= 0xd800 && c <= 0xdfff) {
        c = 0xfffd;
      }
      if (c < 0x80) {
        out.push(c);
      } else if (c < 0x800) {
        out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      } else if (c < 0x10000) {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      } else {
        out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      }
    }
    return new Uint8Array(out);
  }

  function bytesOf(input) {
    if (input === undefined) {
      return new Uint8Array(0);
    }
    if (input instanceof ArrayBuffer) {
      return new Uint8Array(input);
    }
    if (ArrayBuffer.isView(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    throw new TypeError("decode takes an ArrayBuffer or a view of one");
  }

  // UTF-8 as the Encoding Standard decodes it: one U+FFFD per maximal invalid subpart.
  function decode(input) {
    const b = bytesOf(input);
    const parts = [];
    let i = b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf ? 3 : 0;
    while (i < b.length) {
      const c = b[i];
      if (c < 0x80) {
        parts.push(String.fromCharCode(c));
        i++;
        continue;
      }
      let n = 0;
      let cp = 0;
      if (c >= 0xc2 && c <= 0xdf) {
        n = 1;
        cp = c & 0x1f;
      } else if (c >= 0xe0 && c <= 0xef) {
        n = 2;
        cp = c & 0x0f;
      } else if (c >= 0xf0 && c <= 0xf4) {
        n = 3;
        cp = c & 0x07;
      } else {
        parts.push("�");
        i++;
        continue;
      }
      let lo = 0x80;
      let hi = 0xbf;
      if (c === 0xe0) {
        lo = 0xa0;
      } else if (c === 0xed) {
        hi = 0x9f;
      } else if (c === 0xf0) {
        lo = 0x90;
      } else if (c === 0xf4) {
        hi = 0x8f;
      }
      let j = 1;
      for (; j <= n; j++) {
        const d = b[i + j];
        if (d === undefined || d < lo || d > hi) {
          break;
        }
        lo = 0x80;
        hi = 0xbf;
        cp = (cp << 6) | (d & 0x3f);
      }
      i += j;
      parts.push(j <= n ? "�" : String.fromCodePoint(cp));
    }
    return parts.join("");
  }

  class TextEncoder {
    get encoding() {
      return "utf-8";
    }
    encode(input = "") {
      return encode(input);
    }
  }

  class TextDecoder {
    constructor(label = "utf-8") {
      const name = String(label).trim().toLowerCase();
      if (name !== "utf-8" && name !== "utf8" && name !== "unicode-1-1-utf-8") {
        throw new RangeError("only utf-8 is supported");
      }
    }
    get encoding() {
      return "utf-8";
    }
    decode(input) {
      return decode(input);
    }
  }

  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  function btoa(input) {
    const s = String(input);
    const out = [];
    for (let i = 0; i < s.length; i += 3) {
      const a = s.charCodeAt(i);
      const b = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      const c = i + 2 < s.length ? s.charCodeAt(i + 2) : 0;
      if (a > 255 || b > 255 || c > 255) {
        throw new TypeError("btoa takes characters of one byte");
      }
      const n = (a << 16) | (b << 8) | c;
      out.push(
        ALPHABET[n >> 18],
        ALPHABET[(n >> 12) & 63],
        i + 1 < s.length ? ALPHABET[(n >> 6) & 63] : "=",
        i + 2 < s.length ? ALPHABET[n & 63] : "=",
      );
    }
    return out.join("");
  }

  // The forgiving-base64 decode of the HTML standard.
  function atob(input) {
    let s = String(input).replace(/[\t\n\f\r ]/g, "");
    if (s.length % 4 === 0) {
      s = s.replace(/={1,2}$/, "");
    }
    if (s.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(s)) {
      throw new TypeError("atob takes base64");
    }
    const out = [];
    let bits = 0;
    let have = 0;
    for (let i = 0; i < s.length; i++) {
      bits = (bits << 6) | ALPHABET.indexOf(s[i]);
      have += 6;
      if (have >= 8) {
        have -= 8;
        out.push(String.fromCharCode((bits >> have) & 0xff));
      }
    }
    return out.join("");
  }

  for (const [name, value] of [
    ["TextEncoder", TextEncoder],
    ["TextDecoder", TextDecoder],
    ["btoa", btoa],
    ["atob", atob],
  ]) {
    Object.defineProperty(g, name, { value, writable: true, configurable: true, enumerable: false });
  }
})(globalThis);
