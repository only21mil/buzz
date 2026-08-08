import * as React from "react";

import { useUsersBatchQuery } from "@/features/profile/hooks";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import type {
  ChannelMember,
  ManagedAgent,
  RelayAgent,
} from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

export function useCandidateProfiles(
  members: ChannelMember[] | undefined,
  managedAgents: ManagedAgent[] | undefined,
  relayAgents: RelayAgent[] | undefined,
  providedProfiles: UserProfileLookup | undefined,
): {
  candidateProfiles: UserProfileLookup;
  memberPubkeys: ReadonlySet<string>;
} {
  const memberPubkeys = React.useMemo(
    () =>
      new Set((members ?? []).map((member) => normalizePubkey(member.pubkey))),
    [members],
  );
  const candidatePubkeys = React.useMemo(
    () =>
      [
        ...new Set([
          ...memberPubkeys,
          ...(managedAgents ?? []).map(({ pubkey }) => normalizePubkey(pubkey)),
          ...(relayAgents ?? []).map(({ pubkey }) => normalizePubkey(pubkey)),
        ]),
      ].filter((pubkey) => !providedProfiles?.[pubkey]),
    [managedAgents, memberPubkeys, providedProfiles, relayAgents],
  );
  const profilesQuery = useUsersBatchQuery(candidatePubkeys, {
    enabled: candidatePubkeys.length > 0,
  });

  const candidateProfiles = React.useMemo(
    () => ({
      ...(profilesQuery.data?.profiles ?? {}),
      ...(providedProfiles ?? {}),
    }),
    [profilesQuery.data?.profiles, providedProfiles],
  );

  return { candidateProfiles, memberPubkeys };
}
