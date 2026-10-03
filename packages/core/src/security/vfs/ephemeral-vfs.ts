/**
 * Ephemeral Virtual Filesystem
 *
 * Wraps file-system tool calls in a copy-on-write virtual filesystem that
 * rolls back state upon error or session termination. Uses an in-memory
 * layer that shadows the real filesystem — reads fall through to the host
 * FS, writes are captured in memory and discarded on rollback.
 */

import { readFile as fsReadFile, writeFile as fsWriteFile, mkdir as fsMkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

export interface VfsStats {
  isFile(): boolean;
  isDirectory(): boolean;
  size: number;
}

export interface VfsFile {
  content: Buffer;
  mode: number;
}

/**
 * Copy-on-write virtual filesystem layer.
 *
 * - Reads: served from the in-memory overlay first, then the host FS.
 * - Writes: captured in memory only (copy-on-write).
 * - Rollback: discards all in-memory writes, restoring the original state.
 * - Commit: flushes in-memory writes to the host FS (optional).
 */
export class EphemeralVfs {
  readonly #overlay = new Map<string, VfsFile>();
  readonly #directories = new Set<string>();
  readonly #root: string;
  #committed = false;

  constructor(root: string = process.cwd()) {
    this.#root = resolve(root);
  }

  get root(): string {
    return this.#root;
  }

  get isCommitted(): boolean {
    return this.#committed;
  }

  /** Read a file. Falls back to the host FS when not in the overlay. */
  async readFile(path: string): Promise<Buffer> {
    const key = this.#key(path);
    const entry = this.#overlay.get(key);
    if (entry) return entry.content;
    return fsReadFile(resolve(this.#root, path));
  }

  /** Read a file as a UTF-8 string. */
  async readFileString(path: string): Promise<string> {
    const buf = await this.readFile(path);
    return buf.toString('utf8');
  }

  /** Write a file into the overlay (copy-on-write). */
  async writeFile(path: string, content: Buffer | string): Promise<void> {
    const key = this.#key(path);
    const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
    this.#overlay.set(key, { content: buf, mode: 0o644 });
    // Ensure parent directories exist in the overlay.
    const parts = key.split('/');
    for (let i = 1; i < parts.length; i += 1) {
      this.#directories.add(parts.slice(0, i).join('/'));
    }
  }

  /** Create a directory in the overlay. */
  async mkdir(path: string): Promise<void> {
    this.#directories.add(this.#key(path));
  }

  /** Check if a file exists (overlay or host FS). */
  async exists(path: string): Promise<boolean> {
    const key = this.#key(path);
    if (this.#overlay.has(key)) return true;
    if (this.#directories.has(key)) return true;
    try {
      await fsReadFile(resolve(this.#root, path));
      return true;
    } catch {
      return false;
    }
  }

  /** List files in a directory (overlay + host FS). */
  async readdir(path: string): Promise<string[]> {
    const key = this.#key(path);
    const results = new Set<string>();
    for (const overlayKey of this.#overlay.keys()) {
      if (overlayKey.startsWith(`${key}/`)) {
        const rest = overlayKey.slice(key.length + 1);
        const first = rest.split('/')[0];
        if (first) results.add(first);
      }
    }
    for (const dir of this.#directories) {
      if (dir.startsWith(`${key}/`)) {
        const rest = dir.slice(key.length + 1);
        const first = rest.split('/')[0];
        if (first) results.add(first);
      }
    }
    return [...results];
  }

  /** Rollback all in-memory writes, restoring the original state. */
  rollback(): void {
    this.#overlay.clear();
    this.#directories.clear();
    this.#committed = false;
  }

  /** Commit all in-memory writes to the host FS. */
  async commit(): Promise<void> {
    for (const [key, entry] of this.#overlay) {
      const hostPath = resolve(this.#root, key);
      await fsMkdir(resolve(hostPath, '..'), { recursive: true });
      await fsWriteFile(hostPath, entry.content);
    }
    this.#committed = true;
  }

  /** Get statistics about the overlay. */
  stats(): { files: number; directories: number; totalBytes: number } {
    let totalBytes = 0;
    for (const entry of this.#overlay.values()) {
      totalBytes += entry.content.length;
    }
    return {
      files: this.#overlay.size,
      directories: this.#directories.size,
      totalBytes,
    };
  }

  #key(path: string): string {
    const resolved = resolve(this.#root, path);
    return resolved.startsWith(this.#root)
      ? resolved.slice(this.#root.length + 1)
      : resolved;
  }
}

/**
 * Session-scoped VFS manager. Each session gets its own ephemeral filesystem
 * that is automatically rolled back when the session ends.
 */
export class VfsSessionManager {
  readonly #sessions = new Map<string, EphemeralVfs>();

  getOrCreate(sessionId: string, root?: string): EphemeralVfs {
    let vfs = this.#sessions.get(sessionId);
    if (!vfs) {
      vfs = new EphemeralVfs(root);
      this.#sessions.set(sessionId, vfs);
    }
    return vfs;
  }

  get(sessionId: string): EphemeralVfs | undefined {
    return this.#sessions.get(sessionId);
  }

  /** Rollback and remove a session's VFS. */
  destroy(sessionId: string): void {
    const vfs = this.#sessions.get(sessionId);
    if (vfs) {
      vfs.rollback();
      this.#sessions.delete(sessionId);
    }
  }

  /** Rollback and remove all sessions. */
  destroyAll(): void {
    for (const vfs of this.#sessions.values()) {
      vfs.rollback();
    }
    this.#sessions.clear();
  }

  get sessionCount(): number {
    return this.#sessions.size;
  }
}
