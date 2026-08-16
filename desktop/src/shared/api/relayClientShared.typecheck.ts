import type { RelayHistoryFilters } from "./relayClientShared";

type AssertFalse<Value extends false> = Value;

/** Compile-time guard: history requests cannot be constructed with no filter. */
export type RelayHistoryFiltersRejectEmptyTuple = AssertFalse<
  readonly [] extends RelayHistoryFilters ? true : false
>;
