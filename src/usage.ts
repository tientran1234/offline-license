import { ChainedLedger, type ChainedLedgerOptions } from "./ledger.js";
import { bindMachine } from "./machine.js";

export type UsageLedgerOptions = Omit<ChainedLedgerOptions, "mac">;

/**
 * The Node build's usage ledger.
 *
 * All it adds to `ChainedLedger` is the HMAC, and the HMAC is `bindMachine` —
 * the same keyed-by-license-id primitive the machine binding uses, so there is
 * one hash in this library and not two. The browser build adds its own, which
 * produces the same bytes, so a ledger written here reads back there.
 */
export class UsageLedger extends ChainedLedger {
  constructor(options: UsageLedgerOptions) {
    super({ ...options, mac: bindMachine });
  }
}
