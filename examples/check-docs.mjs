import { readFileSync } from 'node:fs';

const lines = readFileSync('DOCUMENTATION.md', 'utf8').split(/\r?\n/);

/** Split a table row on pipes that are not backslash-escaped. */
const cells = (line) => line.split(/(?<!\\)\|/).length - 1;

let block = [];
let issues = 0;

const flush = () => {
  if (block.length >= 2) {
    const counts = block.map(([, line]) => cells(line));
    const first = counts[0];
    const bad = block.filter((_, i) => counts[i] !== first);
    if (bad.length > 0) {
      issues += 1;
      console.log(`MISMATCH at line ${block[0][0] + 1}: counts=${counts.join(',')}`);
      for (const [i, line] of bad) console.log(`   ${i + 1}: ${line.slice(0, 90)}`);
    }
    const sep = block[1][1];
    if (!/^\|[\s:|-]+\|\s*$/.test(sep)) {
      issues += 1;
      console.log(`BAD SEPARATOR at line ${block[1][0] + 1}: ${sep}`);
    }
  }
  block = [];
};

lines.forEach((line, index) => {
  if (/^\|/.test(line)) block.push([index, line]);
  else flush();
});
flush();

// Fenced code blocks must be balanced.
const fences = lines.filter((line) => /^```/.test(line)).length;
if (fences % 2 !== 0) {
  issues += 1;
  console.log(`UNBALANCED code fences: ${fences}`);
}

// Every internal anchor referenced must exist as a heading slug.
// Mirrors github-slugger: strip punctuation, then map *each* space to a hyphen
// (so "Quickstart & Installation" → "quickstart--installation").
const slugs = new Set(
  lines
    .filter((line) => /^#{1,6} /.test(line))
    .map((line) =>
      line
        .replace(/^#+\s+/, '')
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .trim()
        .replace(/ /g, '-'),
    ),
);
const anchors = [...new Set([...readFileSync('DOCUMENTATION.md', 'utf8').matchAll(/\]\(#([^)]+)\)/g)].map((m) => m[1]))];
const missing = anchors.filter((a) => !slugs.has(a));
if (missing.length > 0) {
  issues += 1;
  console.log('BROKEN anchors:', missing.join(', '));
}

console.log(`table/fence/anchor issues: ${issues}`);
console.log(`headings: ${slugs.size} · lines: ${lines.length} · internal links: ${anchors.length}`);
