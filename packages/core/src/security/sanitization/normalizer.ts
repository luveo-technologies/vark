/**
 * Input Normalization
 *
 * Unicode normalization, zero-width character stripping, homoglyph folding,
 * and recursive layer decoding before any scanning gate executes.
 */

export interface NormalizerConfig {
  /** Maximum recursive decode depth. @default 5 */
  maxDecodeDepth?: number;
  /** Unicode normalization form. @default 'NFKC' */
  normalizationForm?: 'NFC' | 'NFD' | 'NFKC' | 'NFKD';
  /** Whether to fold homoglyphs to ASCII. @default true */
  foldHomoglyphs?: boolean;
  /** Whether to decode HTML entities. @default true */
  decodeHtmlEntities?: boolean;
  /** Whether to decode URL encoding. @default true */
  decodeUrl?: boolean;
  /** Whether to decode base64. @default true */
  decodeBase64?: boolean;
  /** Whether to decode hex encoding. @default true */
  decodeHex?: boolean;
}

// Zero-width and invisible characters
const ZERO_WIDTH_CHARS = /[\u200B-\u200D\uFEFF\u2060-\u2064]/g;

// Bidi control characters
const BIDI_CHARS = /[\u200E-\u200F\u202A-\u202E\u2066-\u2069]/g;

// Homoglyph mapping: visually similar Unicode chars → ASCII equivalents
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0445': 'x', '\u0455': 's', '\u0456': 'i', '\u0458': 'j',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
  '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
  '\u0425': 'X', '\u0443': 'y',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
  '\u04CF': 'l', '\u04BB': 'h',
  '\uFF10': '0', '\uFF11': '1', '\uFF12': '2', '\uFF13': '3', '\uFF14': '4',
  '\uFF15': '5', '\uFF16': '6', '\uFF17': '7', '\uFF18': '8', '\uFF19': '9',
  '\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D', '\uFF25': 'E',
  '\uFF26': 'F', '\uFF27': 'G', '\uFF28': 'H', '\uFF29': 'I', '\uFF2A': 'J',
  '\uFF2B': 'K', '\uFF2C': 'L', '\uFF2D': 'M', '\uFF2E': 'N', '\uFF2F': 'O',
  '\uFF30': 'P', '\uFF31': 'Q', '\uFF32': 'R', '\uFF33': 'S', '\uFF34': 'T',
  '\uFF35': 'U', '\uFF36': 'V', '\uFF37': 'W', '\uFF38': 'X', '\uFF39': 'Y',
  '\uFF3A': 'Z',
  '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
  '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
  '\uFF4B': 'k', '\uFF4C': 'l', '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o',
  '\uFF50': 'p', '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
  '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x', '\uFF59': 'y',
  '\uFF5A': 'z',
};

/**
 * Normalize input text: Unicode NFKC, strip zero-width/bidi chars, fold homoglyphs.
 */
export function normalizeInput(text: string, config: NormalizerConfig = {}): string {
  const normalizationForm = config.normalizationForm ?? 'NFKC';
  const foldHomoglyphs = config.foldHomoglyphs ?? true;

  let result = text;

  // Unicode normalization
  result = result.normalize(normalizationForm);

  // Strip zero-width characters
  result = result.replace(ZERO_WIDTH_CHARS, '');

  // Strip bidi control characters
  result = result.replace(BIDI_CHARS, '');

  // Fold homoglyphs to ASCII
  if (foldHomoglyphs) {
    result = result
      .split('')
      .map((char) => HOMOGLYPH_MAP[char] ?? char)
      .join('');
  }

  return result;
}

/**
 * Canonicalize text for scanning: identity for pure-ASCII input (NFKC,
 * zero-width stripping and homoglyph folding cannot change it), otherwise
 * the full {@link normalizeInput} pipeline.
 *
 * Lets scanners see through visual-spoofing obfuscation (zero-width
 * joiners, full-width lookalikes, bidi controls) without paying for
 * normalization on clean input.
 */
// eslint-disable-next-line no-control-regex -- the full ASCII range includes control chars by definition
const ASCII_ONLY = /^[\x00-\x7F]*$/;

export function normalizeForScan(text: string, config: NormalizerConfig = {}): string {
  if (ASCII_ONLY.test(text)) return text;
  return normalizeInput(text, config);
}

/**
 * Decode HTML entities (named and numeric).
 */
export function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * Decode URL encoding (percent-encoding).
 */
export function decodeUrlEncoding(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

/**
 * Decode hex encoding (e.g., `48656c6c6f` → `Hello`).
 */
export function decodeHexEncoding(text: string): string {
  const cleaned = text.replace(/[^0-9a-fA-F]/g, '');
  if (cleaned.length % 2 !== 0 || cleaned.length === 0) return '';
  let result = '';
  for (let i = 0; i < cleaned.length; i += 2) {
    result += String.fromCharCode(parseInt(cleaned.slice(i, i + 2), 16));
  }
  return result;
}

/**
 * Decode base64 encoding.
 */
function decodeBase64Impl(text: string): string {
  try {
    const cleaned = text.replace(/[^A-Za-z0-9+/=]/g, '');
    if (cleaned.length === 0) return '';
    return Buffer.from(cleaned, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

/**
 * Recursively decode all encoding layers up to maxDepth.
 * Returns all intermediate and fully decoded payloads for scanning.
 */
export function decodeAllLayers(
  text: string,
  config: NormalizerConfig = {},
): string[] {
  const maxDepth = config.maxDecodeDepth ?? 5;
  const decodeHtml = config.decodeHtmlEntities ?? true;
  const decodeUrl = config.decodeUrl ?? true;
  const decodeBase64 = config.decodeBase64 ?? true;
  const decodeHex = config.decodeHex ?? true;

  const results: string[] = [text];
  let current = text;

  for (let depth = 0; depth < maxDepth; depth += 1) {
    let decoded = current;

    if (decodeUrl) decoded = decodeUrlEncoding(decoded);
    if (decodeHtml) decoded = decodeHtmlEntities(decoded);
    if (decodeHex) {
      const hexDecoded = decodeHexEncoding(decoded);
      if (hexDecoded && hexDecoded !== decoded) decoded = hexDecoded;
    }
    if (decodeBase64) {
      const b64Decoded = decodeBase64Impl(decoded);
      if (b64Decoded && b64Decoded !== decoded) decoded = b64Decoded;
    }

    if (decoded === current) break;
    results.push(decoded);
    current = decoded;
  }

  return results;
}

/**
 * Full normalization pipeline: normalize + decode all layers.
 * Returns all payload variants that should be scanned.
 */
export function normalizeAndDecode(
  text: string,
  config: NormalizerConfig = {},
): string[] {
  const normalized = normalizeInput(text, config);
  const layers = decodeAllLayers(normalized, config);
  // Also include the normalized-but-not-decoded version
  return [normalized, ...layers.filter((l) => l !== normalized)];
}

// ── Strict runtime decoding ─────────────────────────────────────────────────
// decodeAllLayers() above is intentionally aggressive: it decodes anything
// that *can* decode, which is right for the `vark scan` analysis tool where a
// human reviews every variant. The runtime gate below is stricter — it only
// decodes strings that exhibit *explicit encoding markers*, and only keeps
// variants that look like text. That keeps opaque tokens (git SHAs, UUIDs,
// session IDs — all valid base64/hex shapes) from decoding into random bytes
// and tripping single-character signatures.

/** One decoded variant plus the decoder chain that produced it. */
export interface DecodedVariant {
  text: string;
  /** Decoder names applied in order, e.g. `['base64', 'url']`. */
  via: string[];
}

/** Maximum decoded variants examined per input string. */
const MAX_DECODED_VARIANTS = 16;

/** Decoded variants longer than this are skipped (blowup guard). */
const MAX_DECODED_BYTES = 65_536;

/**
 * Minimum fraction of printable ASCII (0x20–0x7E plus tab/LF/CR) a decoded
 * variant must contain to be scanned. Random binary decodes to ~30–40%;
 * genuine smuggled commands are ~100%.
 */
const MIN_PRINTABLE_RATIO = 0.7;

/** Minimum decoded length worth scanning. */
const MIN_DECODED_LENGTH = 4;

function isPrintableText(text: string): boolean {
  if (text.length < MIN_DECODED_LENGTH || text.length > MAX_DECODED_BYTES) return false;
  let printable = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d) {
      printable += 1;
    }
  }
  return printable / text.length >= MIN_PRINTABLE_RATIO;
}

interface StrictDecoder {
  name: 'url' | 'html' | 'hex' | 'base64';
  /** Cheap marker test: does the input even look like this encoding? */
  looksEncoded(value: string): boolean;
  decode(value: string): string;
}

const STRICT_DECODERS: readonly StrictDecoder[] = [
  {
    name: 'url',
    looksEncoded: (value) => /%[0-9A-Fa-f]{2}/.test(value),
    decode: decodeUrlEncoding,
  },
  {
    name: 'html',
    looksEncoded: (value) => /&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);/.test(value),
    decode: decodeHtmlEntities,
  },
  {
    name: 'hex',
    // Whole trimmed string must be even-length hex, minimum 8 chars.
    // (A git SHA matches this shape — the printability gate below is what
    // keeps its random-byte decode from tripping signatures.)
    looksEncoded: (value) => /^(?:[0-9a-fA-F]{2}){4,}$/.test(value.replace(/\s+/g, '')),
    decode: decodeHexEncoding,
  },
  {
    name: 'base64',
    looksEncoded: (value) => {
      const compact = value.replace(/\s+/g, '');
      return (
        compact.length >= 12 &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)
      );
    },
    decode: decodeBase64Impl,
  },
];

/**
 * Decode only strings with explicit encoding markers, following nested layers
 * (base64→hex→URL, …) up to `maxDecodeDepth`. Every emitted variant is
 * text-like per {@link MIN_PRINTABLE_RATIO}.
 *
 * This is the runtime-gate counterpart to {@link decodeAllLayers}: same
 * decoders, but strict admission so opaque tokens never become block
 * decisions.
 */
export function decodeEncodedLayers(
  text: string,
  config: NormalizerConfig = {},
): DecodedVariant[] {
  const maxDepth = config.maxDecodeDepth ?? 5;
  const out: DecodedVariant[] = [];
  const seen = new Set<string>([text]);
  let frontier: DecodedVariant[] = [{ text, via: [] }];

  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth += 1) {
    const next: DecodedVariant[] = [];
    for (const { text: current, via } of frontier) {
      for (const decoder of STRICT_DECODERS) {
        if (!decoder.looksEncoded(current)) continue;
        let decoded: string;
        try {
          decoded = decoder.decode(current);
        } catch {
          continue;
        }
        if (!decoded || decoded === current || seen.has(decoded)) continue;
        if (!isPrintableText(decoded)) continue;
        seen.add(decoded);
        const variant: DecodedVariant = { text: decoded, via: [...via, decoder.name] };
        out.push(variant);
        if (out.length >= MAX_DECODED_VARIANTS) return out;
        next.push(variant);
      }
    }
    frontier = next;
  }

  return out;
}
