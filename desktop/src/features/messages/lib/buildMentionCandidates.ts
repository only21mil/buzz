import type {
  AgentPersona,
  ChannelMember,
  ManagedAgent,
  RelayAgent,
  UserSearchResult,
} from "@/shared/api/types";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import { normalizePubkey } from "@/shared/lib/pubkey";
import {
  coalesceAgentAutocompleteCandidates,
  coalesceAutocompleteCandidatesByKey,
  isAgentIdentityInAllowedList,
  isAgentIdentityInManagedList as isManagedIdentity,
  shouldHideAgentFromMentions,
} from "@/features/agents/lib/agentAutocompleteEligibility";
import {
  formatSearchUserDisplayName,
  formatSearchUserSecondaryLabel,
} from "./mentionUserLabels";
import {
  globalSearchIdentityKey,
  mentionCandidateLabel,
  type MentionCandidate,
} from "./mentionCandidates";

type Options = {
  activeAgentPubkeys: ReadonlySet<string>;
  activePersonaById: ReadonlyMap<string, AgentPersona>;
  activePersonas: AgentPersona[];
  candidateProfiles: UserProfileLookup;
  userSearchResults: UserSearchResult[];
  canSearchGlobalUsers: boolean;
  currentPubkey: string | null;
  directoryAgentPubkeys: ReadonlySet<string>;
  isArchivedDiscovery: (pubkey: string) => boolean;
  managedAgentNamesByPubkey: ReadonlyMap<string, string>;
  managedAgentPersonaIds: ReadonlySet<string>;
  managedAgentPersonaIdsByPubkey: ReadonlyMap<string, string>;
  managedAgentPubkeys: ReadonlySet<string>;
  managedAgents: ManagedAgent[] | undefined;
  memberPubkeys: ReadonlySet<string>;
  members: ChannelMember[] | undefined;
  mentionableAgentPubkeys: ReadonlySet<string>;
  personaNameByPubkey: ReadonlyMap<string, string>;
  relayAgentNamesByPubkey: ReadonlyMap<string, string>;
  relayAgents: RelayAgent[] | undefined;
};

/** Merge roster, hydrated profiles and owner-eligible discovery without losing identity. */
export function buildMentionCandidates({
  activeAgentPubkeys,
  activePersonaById,
  activePersonas,
  candidateProfiles,
  userSearchResults,
  canSearchGlobalUsers,
  currentPubkey,
  directoryAgentPubkeys,
  isArchivedDiscovery,
  managedAgentNamesByPubkey,
  managedAgentPersonaIds,
  managedAgentPersonaIdsByPubkey,
  managedAgentPubkeys,
  managedAgents,
  memberPubkeys,
  members,
  mentionableAgentPubkeys,
  personaNameByPubkey,
  relayAgentNamesByPubkey,
  relayAgents,
}: Options): MentionCandidate[] {
  const candidatesByPubkey = new Map<string, MentionCandidate>();

  const addCandidate = (candidate: MentionCandidate & { pubkey: string }) => {
    const pubkey = normalizePubkey(candidate.pubkey);
    if (isArchivedDiscovery(pubkey)) {
      return;
    }
    if (
      !isManagedIdentity(candidate, managedAgentPubkeys, currentPubkey) &&
      !isAgentIdentityInAllowedList(candidate, mentionableAgentPubkeys)
    ) {
      return;
    }
    if (
      shouldHideAgentFromMentions({
        ...candidate,
        pubkey,
        currentPubkey,
        relayAgents: relayAgents,
        mentionableAgentPubkeys,
        directoryAgentPubkeys,
      })
    ) {
      return;
    }
    const current = candidatesByPubkey.get(pubkey);
    if (!current) {
      candidatesByPubkey.set(pubkey, { ...candidate, pubkey });
      return;
    }

    candidatesByPubkey.set(pubkey, {
      ...current,
      avatarUrl: current.avatarUrl ?? candidate.avatarUrl ?? null,
      displayName:
        current.isAgent && !candidate.isAgent
          ? current.displayName
          : candidate.isAgent && !current.isAgent
            ? (candidate.displayName ?? current.displayName)
            : (current.displayName ?? candidate.displayName),
      isAgent: current.isAgent || candidate.isAgent,
      isActiveAgent: current.isActiveAgent || candidate.isActiveAgent,
      isMember: current.isMember || candidate.isMember,
      personaId: current.personaId ?? candidate.personaId,
      personaName: current.personaName ?? candidate.personaName ?? null,
      role: current.role ?? candidate.role ?? null,
      secondaryLabel:
        current.secondaryLabel ?? candidate.secondaryLabel ?? null,
      ownerPubkey:
        current.ownerPubkey ??
        candidate.ownerPubkey ??
        (candidate.isAgent && candidate.pubkey
          ? candidateProfiles[pubkey]?.ownerPubkey
          : null) ??
        null,
      isManagedAgent: current.isManagedAgent || candidate.isManagedAgent,
    });
  };
  for (const member of members ?? []) {
    const pubkey = normalizePubkey(member.pubkey);
    const linkedPersonaId = activePersonaById.has(pubkey) ? pubkey : undefined;
    const agentName =
      managedAgentNamesByPubkey.get(pubkey) ??
      relayAgentNamesByPubkey.get(pubkey) ??
      null;
    const profile = candidateProfiles[pubkey] ?? null;
    addCandidate({
      kind: "identity",
      pubkey,
      displayName:
        member.displayName?.trim() ||
        agentName ||
        profile?.displayName?.trim() ||
        profile?.nip05Handle?.trim() ||
        null,
      avatarUrl: profile?.avatarUrl ?? null,
      isMember: true,
      isActiveAgent: activeAgentPubkeys.has(pubkey),
      personaId: managedAgentPersonaIdsByPubkey.get(pubkey) ?? linkedPersonaId,
      isAgent:
        member.isAgent === true ||
        profile?.isAgent === true ||
        member.role === "bot" ||
        managedAgentNamesByPubkey.has(pubkey) ||
        relayAgentNamesByPubkey.has(pubkey),
      ownerPubkey: profile?.ownerPubkey ?? null,
      personaName: personaNameByPubkey.get(pubkey) ?? null,
      role: member.role,
      secondaryLabel:
        profile?.displayName?.trim() && profile?.nip05Handle?.trim()
          ? profile.nip05Handle
          : null,
    });
  }

  for (const agent of relayAgents ?? []) {
    const pubkey = normalizePubkey(agent.pubkey);
    addCandidate({
      kind: "identity",
      pubkey,
      displayName: agent.name,
      isMember: false,
      isActiveAgent: activeAgentPubkeys.has(normalizePubkey(agent.pubkey)),
      personaId:
        managedAgentPersonaIdsByPubkey.get(pubkey) ??
        (activePersonaById.has(pubkey) ? pubkey : undefined),
      ownerPubkey: agent.ownerPubkey ?? null,
      isAgent: true,
    });
  }

  for (const agent of managedAgents ?? []) {
    addCandidate({
      kind: "identity",
      pubkey: agent.pubkey,
      displayName: agent.name,
      isMember: false,
      isActiveAgent: activeAgentPubkeys.has(normalizePubkey(agent.pubkey)),
      isAgent: true,
      isManagedAgent: true,
      personaId: agent.personaId ?? undefined,
      personaName:
        personaNameByPubkey.get(normalizePubkey(agent.pubkey)) ?? null,
      ownerPubkey: currentPubkey,
    });
  }

  if (canSearchGlobalUsers) {
    for (const user of userSearchResults) {
      const pubkey = normalizePubkey(user.pubkey);
      addCandidate({
        kind: "identity",
        pubkey,
        displayName: formatSearchUserDisplayName(user),
        avatarUrl: user.avatarUrl ?? null,
        personaId:
          managedAgentPersonaIdsByPubkey.get(pubkey) ??
          (activePersonaById.has(pubkey) ? pubkey : undefined),
        isMember: false,
        isAgent:
          user.isAgent ||
          managedAgentNamesByPubkey.has(pubkey) ||
          relayAgentNamesByPubkey.has(pubkey),
        personaName: personaNameByPubkey.get(pubkey) ?? null,
        secondaryLabel: formatSearchUserSecondaryLabel(user),
        ownerPubkey: user.ownerPubkey ?? null,
        isGlobalSearchResult: true,
        isManagedAgent: managedAgentNamesByPubkey.has(pubkey),
      });
    }
  }

  const personaCandidates: MentionCandidate[] = activePersonas
    .filter((persona) => !managedAgentPersonaIds.has(persona.id))
    .map((persona) => ({
      kind: "persona" as const,
      personaId: persona.id,
      displayName: persona.displayName,
      avatarUrl: persona.avatarUrl,
      isMember: false,
      isAgent: true,
    }))
    .filter((candidate) => candidate.displayName.trim().length > 0);

  return coalesceAgentAutocompleteCandidates(
    coalesceAutocompleteCandidatesByKey(
      [...candidatesByPubkey.values(), ...personaCandidates],
      globalSearchIdentityKey,
    ),
    {
      currentPubkey,
      getLabel: mentionCandidateLabel,
      preferredPubkeys: memberPubkeys,
    },
  );
}
