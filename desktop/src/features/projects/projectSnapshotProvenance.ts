const snapshotRows = new WeakSet<object>();

/** Cached projections are display-only, including copies made before a live read. */
export function isProjectSnapshotRow(project: object): boolean {
  return snapshotRows.has(project);
}

/** Mark a projection rebuilt from persisted events as display-only. */
export function markProjectSnapshotRow(project: object): void {
  snapshotRows.add(project);
}

/** Carry cached provenance across optimistic copies without promoting authority. */
export function preserveProjectSnapshotProvenance<T extends object>(
  source: object,
  copy: T,
): T {
  if (isProjectSnapshotRow(source)) markProjectSnapshotRow(copy);
  return copy;
}
