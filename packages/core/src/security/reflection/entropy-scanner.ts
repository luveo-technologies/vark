/**
 * Entropy & Reflection Scanner
 *
 * Measures output entropy and similarity scores against system context to
 * block prompt leaking or context reflection attacks. High-entropy output
 * that closely resembles system prompts is flagged as a potential leak.
 */

export interface EntropyScanResult {
  /** Shannon entropy of the output (bits per character). */
  entropy: number;
  /** Similarity score against system context (0–1). */
  similarity: number;
  /** Whether the output is flagged as a potential leak. */
  flagged: boolean;
  /** Reason for flagging. */
  reason?: string;
}

export interface EntropyConfig {
  /** Entropy threshold in bits/char. @default 5.5 */
  entropyThreshold?: number;
  /** Similarity threshold (0–1). @default 0.85 */
  similarityThreshold?: number;
  /** Minimum output length to scan. @default 50 */
  minLength?: number;
  /** System context strings to compare against. */
  systemContext?: string[];
}

/**
 * Calculate Shannon entropy of a string (bits per character).
 */
export function calculateEntropy(text: string): number {
  if (text.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const char of text) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = text.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Calculate Jaccard similarity between two strings (token-based).
 */
export function jaccardSimilarity(a: string, b: string): number {
  const tokensA = new Set(a.toLowerCase().split(/\s+/).filter(Boolean));
  const tokensB = new Set(b.toLowerCase().split(/\s+/).filter(Boolean));
  if (tokensA.size === 0 && tokensB.size === 0) return 1;
  let intersection = 0;
  for (const token of tokensA) {
    if (tokensB.has(token)) intersection += 1;
  }
  const union = tokensA.size + tokensB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Calculate cosine similarity between two strings (character n-gram based).
 */
export function ngramCosineSimilarity(a: string, b: string, n = 3): number {
  const getNgrams = (text: string): Map<string, number> => {
    const ngrams = new Map<string, number>();
    const padded = ' '.repeat(n - 1) + text.toLowerCase() + ' '.repeat(n - 1);
    for (let i = 0; i < padded.length - n + 1; i += 1) {
      const gram = padded.slice(i, i + n);
      ngrams.set(gram, (ngrams.get(gram) ?? 0) + 1);
    }
    return ngrams;
  };

  const ngramsA = getNgrams(a);
  const ngramsB = getNgrams(b);

  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (const [gram, countA] of ngramsA) {
    normA += countA * countA;
    const countB = ngramsB.get(gram);
    if (countB !== undefined) dot += countA * countB;
  }
  for (const countB of ngramsB.values()) {
    normB += countB * countB;
  }

  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Scan output for entropy anomalies and similarity to system context.
 * Flags potential prompt leaking or context reflection attacks.
 */
export function scanEntropyAndReflection(
  output: string,
  config: EntropyConfig = {},
): EntropyScanResult {
  const entropyThreshold = config.entropyThreshold ?? 5.5;
  const similarityThreshold = config.similarityThreshold ?? 0.85;
  const minLength = config.minLength ?? 50;
  const systemContext = config.systemContext ?? [];

  if (output.length < minLength) {
    return { entropy: 0, similarity: 0, flagged: false };
  }

  const entropy = calculateEntropy(output);

  let maxSimilarity = 0;
  for (const context of systemContext) {
    const sim = ngramCosineSimilarity(output, context);
    if (sim > maxSimilarity) maxSimilarity = sim;
  }

  const flagged = entropy > entropyThreshold && maxSimilarity > similarityThreshold;
  const reason = flagged
    ? `High entropy (${entropy.toFixed(2)} bits/char) with high system context similarity (${maxSimilarity.toFixed(2)}) — potential prompt leak`
    : undefined;

  return { entropy, similarity: maxSimilarity, flagged, reason };
}

/**
 * Create a scanner with system context pre-loaded.
 */
export function createEntropyScanner(systemContext: string[]) {
  return (output: string, config?: Omit<EntropyConfig, 'systemContext'>): EntropyScanResult =>
    scanEntropyAndReflection(output, { ...config, systemContext });
}
