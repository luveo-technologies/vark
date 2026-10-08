export {
  normalizeIp,
  matchWildcardDomain,
  isDomainAllowed,
  stripUrlCredentials,
  checkSsrf,
  checkRedirect,
  checkEgress,
  checkEgressSync,
} from './ssrf-guard.js';
export type { SsrfConfig, SsrfCheckResult, EgressOptions } from './ssrf-guard.js';
