export const CI_REFETCH_INTERVAL_MS = 60_000;

type CiPollingSnapshot = Readonly<{
  statuses: ReadonlyArray<Readonly<{ state: string }>>;
  failures: ReadonlyArray<
    Readonly<{
      kind: string;
      http_status?: number;
    }>
  >;
}>;

/** Poll only while a run is active or a status failure can recover. */
export function ciRefetchInterval(
  data: CiPollingSnapshot | undefined,
): number | false {
  if (!data) return CI_REFETCH_INTERVAL_MS;

  const hasActiveRun = data.statuses.some(
    (status) => status.state === "pending",
  );
  const hasRetryableFailure = data.failures.some(
    (failure) =>
      failure.kind === "transport" ||
      failure.kind === "unavailable" ||
      failure.http_status === 429,
  );
  return hasActiveRun || hasRetryableFailure ? CI_REFETCH_INTERVAL_MS : false;
}
