import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { verifyEvent } from "nostr-tools/pure";
import type { RelayEvent } from "@/shared/api/types";

type ChannelMember = {
  pubkey: string;
  role: string;
  is_agent: boolean;
  display_name: string | null;
};

// Match native profile_has_valid_oa_owner: provenance requires exactly one
// auth tag, a valid profile signature, and every signed event-time condition.
function profileHasValidOaOwner(event: RelayEvent): boolean {
  const authTags = event.tags.filter((tag) => tag[0] === "auth");
  const auth = authTags[0];
  if (
    event.kind !== 0 ||
    authTags.length !== 1 ||
    auth.length !== 4 ||
    auth.some((part) => typeof part !== "string")
  ) {
    return false;
  }
  const [, owner, conditions, signature] = auth;
  if (
    !/^[0-9a-f]{64}$/.test(owner) ||
    !/^[0-9a-f]{128}$/.test(signature) ||
    owner === event.pubkey
  ) {
    return false;
  }
  if (
    conditions !== "" &&
    !conditions.split("&").every((clause) => {
      const match = /^(kind=|created_at<|created_at>)(0|[1-9][0-9]*)$/.exec(
        clause,
      );
      if (!match) return false;
      const value = Number(match[2]);
      if (!Number.isSafeInteger(value)) return false;
      if (match[1] === "kind=") return value <= 65_535 && value === event.kind;
      if (value > 4_294_967_295) return false;
      return match[1] === "created_at<"
        ? event.created_at < value
        : event.created_at > value;
    })
  ) {
    return false;
  }
  try {
    return (
      verifyEvent(event) &&
      schnorr.verify(
        hexToBytes(signature),
        sha256(utf8ToBytes(`nostr:agent-auth:${event.pubkey}:${conditions}`)),
        hexToBytes(owner),
      )
    );
  } catch {
    return false;
  }
}

/** Join kind:0 metadata for the complete roster in bounded, sequential batches. */
export async function enrichChannelMemberProfiles(
  members: ChannelMember[],
  client: {
    fetchEvents(filter: {
      kinds: number[];
      authors: string[];
      limit: number;
    }): Promise<RelayEvent[]>;
  },
): Promise<void> {
  for (let offset = 0; offset < members.length; offset += 500) {
    const batch = members.slice(offset, offset + 500);
    let events: RelayEvent[];
    try {
      events = await client.fetchEvents({
        kinds: [0],
        authors: batch.map((member) => member.pubkey),
        limit: batch.length,
      });
    } catch {
      // Profile enrichment is best effort; roster and bot roles stay usable.
      continue;
    }
    const latest = new Map<string, RelayEvent>();
    for (const event of events) {
      if (event.kind !== 0) continue;
      const current = latest.get(event.pubkey);
      if (
        !current ||
        event.created_at > current.created_at ||
        (event.created_at === current.created_at && event.id < current.id)
      ) {
        latest.set(event.pubkey, event);
      }
    }
    for (const member of batch) {
      const event = latest.get(member.pubkey);
      if (!event) continue;
      member.is_agent = member.role === "bot" || profileHasValidOaOwner(event);
      try {
        const profile: unknown = JSON.parse(event.content);
        if (profile && typeof profile === "object" && !Array.isArray(profile)) {
          const content = profile as Record<string, unknown>;
          member.display_name =
            typeof content.display_name === "string"
              ? content.display_name
              : typeof content.name === "string"
                ? content.name
                : null;
        }
      } catch {
        // Ownership is carried by tags, independently of profile JSON.
      }
    }
  }
}
