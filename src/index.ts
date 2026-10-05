export { generateKeyPair, toPrivateKey, toPublicKey } from "./keys.js";
export type { KeyInput, KeyPairPem, KeyRing, PublicKeyInput } from "./keys.js";

export { issue } from "./issue.js";
export { verify, verifyOrThrow } from "./verify.js";
export { LicenseError, TOKEN_PREFIX } from "./core.js";
export type { Predecessor, VerifyFailure, VerifyOptions, VerifyResult } from "./core.js";

export { assertClaims, ClaimsError, featureValue, hasFeature } from "./claims.js";
export type { FeatureValue, Features, LicenseClaims } from "./claims.js";

export { bindMachine, defaultFingerprint } from "./machine.js";

export {
  ACTIVATION_PREFIX,
  ActivationError,
  answersRequest,
  assertMachineClaim,
  createActivationRequest,
  fulfilActivation,
  readActivationRequest,
} from "./activation.js";
export type { ActivationRequestInput, FulfilmentClaims, MachineClaim } from "./activation.js";

export { readLicenseFile, writeLicenseFile, LicenseFileError, LICENSE_FILE_VERSION } from "./file.js";
export type { LicenseFile, LicenseFileInput } from "./file.js";

export { MonotonicClock } from "./clock.js";
export type { ClockObservation, MonotonicClockOptions } from "./clock.js";
export { FileStore, MemoryStore } from "./stores.js";
export type { ClockStore } from "./stores.js";

export { UsageLedger } from "./usage.js";
export type { UsageLedgerOptions } from "./usage.js";
export { parseLedger, serializeLedger, UsageLedgerError, UsageLimitError, USAGE_LEDGER_VERSION } from "./ledger.js";
export type { Ledger, LedgerStore, UsageEntry } from "./ledger.js";
export { FileLedgerStore, MemoryLedgerStore } from "./stores.js";

export { LicenseGuard } from "./guard.js";
export type { LicenseGuardOptions } from "./guard.js";

export { CheckLog, CHECK_LOG_VERSION } from "./audit.js";
export type {
  CheckFailure,
  CheckListener,
  CheckLogOptions,
  CheckLogState,
  CheckLogStore,
  CheckSuccess,
} from "./audit.js";
export { FileCheckLogStore, MemoryCheckLogStore } from "./stores.js";
