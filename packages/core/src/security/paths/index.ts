export {
  containsNullByte,
  expandTilde,
  expandEnvVars,
  parseFileUri,
  isWithinRoots,
  validateWindowsPath,
  checkPathSecurity,
  openFileSafe,
  verifyFileIdentity,
} from './path-security.js';
export type { PathSecurityConfig, PathCheckResult } from './path-security.js';
