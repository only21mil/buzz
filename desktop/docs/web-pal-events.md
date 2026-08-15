# Browser PAL event parity

This is the entry checklist for browser command-port work. It inventories every
static Tauri event subscription in `desktop/src` and reconciles it with every
Tauri event emitted by Rust in `desktop/src-tauri/src` at commit `d302f0d8`.
The dynamic forwarding seam in `desktop/src/testing/e2eBridge.ts:13068` is test
infrastructure, not another event subscription.

The browser event adapter must let every `listen()` call register and clean up
successfully, including events classified as **native-only**. "Silent" means
that no event is dispatched; it must not mean a rejected listener promise.

## Result

| Class | Count | Browser contract |
| --- | ---: | --- |
| `native-only` | 9 | Do not synthesize. The browser has no equivalent native operation; keep the associated command/UI capability disabled or use its separate DOM path. |
| `pal-must-synthesize` | 7 | The named browser PAL command/session handler must dispatch the event with the exact payload shape. |
| `deep-link` | 5 | Parse validated inputs from `window.location`, then dispatch after listeners are available. Community links must also populate the PAL pending-link queue. |
| `huddle` | 10 | Deferred to Wave 5. This includes three renderer-to-renderer events with no Rust emitter. |
| **Total** | **31** | Rust emits 28 of these; three huddle mirror events are emitted only by TypeScript. |

## Highest-value silence hazards

1. **Pairing is a Wave-3 hard gate.** If a browser implementation of
   `start_pairing` or `start_identity_recovery_pairing` returns a QR/session, it
   must subsequently emit `pairing-sas-received` and exactly one terminal
   `pairing-complete`, `pairing-error`, or `pairing-aborted`. Without those
   events, `IdentityRecoveryPairing` and `MobilePairingCard` remain on QR, SAS,
   or transfer state indefinitely. If browser pairing is not implemented, the
   PAL must reject/gate the start command before returning a session.
2. **`huddle-audio-state` is a Wave-5 hard gate.** A non-owner huddle window
   requests state every 500 ms until this event arrives
   (`HuddleContext.tsx:323-337`); silence leaves the room in its microphone-
   unavailable fallback and the retry running forever.
3. **`huddle-state-changed` and `ptt-state` are Wave-5 functional gates.** Some
   huddle views have snapshots or slow polling, but others depend on events for
   teardown and lifecycle changes. Missing `ptt-state` leaves push-to-talk
   closed (safe against audio leakage, but unusable).

Media progress/phase silence does **not** wedge completion: the upload promise
still settles and clears the task. It does freeze the visible progress/phase
until settlement. `agents-data-changed` silence leaves React Query data stale,
but does not hold a pending UI state.

## Authoritative cross-table

Payload shapes below describe the JSON value observed as `event.payload`.
Rust `()` is serialized as `null`.

### PAL must synthesize

| Event | Payload | Renderer listener and effect | Rust emitter and trigger | Owning browser PAL handler |
| --- | --- | --- | --- | --- |
| `agents-data-changed` | `null` | `features/agents/lib/useAgentsDataRefresh.ts:40` — coalesces for 200 ms, then invalidates personas, teams, managed agents, and relay agents. | `commands/personas/inbound.rs:180,313` after an inbound persona/team/managed-agent upsert or tombstone is durably reconciled; `commands/personas/snapshot/import.rs:671` and `commands/team_snapshot.rs:752` after successful import writes. | Command handlers `reconcile_inbound_persona_event`, `confirm_agent_snapshot_import`, and `confirm_team_snapshot_import`, after their browser stores commit. |
| `media-upload-progress` | `{id:string,sent:number,total:number}` | `features/messages/lib/useMediaUpload.ts:195` updates foreground preview percent; `features/messages/lib/backgroundMediaUploadStore.ts:106` updates a correlated background file's byte progress. Both ignore `total <= 0`. | `commands/media_upload_progress.rs:82` after each 64 KiB request-body chunk is yielded, when a `progress_id` exists. | Browser upload handlers for `upload_media_bytes`, `upload_media_bytes_raw`/`uploadMediaFile`, and browser file-picker upload. Use the caller's unchanged progress ID and actual request bytes. |
| `media-upload-phase` | `{id:string,phase:"preparing"|"processing-video"|"converting-image"|"uploading"|"finishing"}` | `features/messages/lib/backgroundMediaUploadStore.ts:132` validates the phase and updates the correlated background file. | `commands/media_upload_progress.rs:122`, called around preparation, video processing, HEIC conversion, request upload, and poster finishing (`commands/media.rs:723-786`). | The same browser media-upload handler that owns the correlated upload. Emit only phases the browser actually performs, in operation order. |
| `pairing-sas-received` | `{sas:string}` | `features/onboarding/ui/IdentityRecoveryPairing.tsx:80` and `features/settings/ui/MobilePairingCard.tsx:296` show the SAS confirmation step for the active session. | `commands/pairing.rs:377` when the active NIP-AB session accepts the peer offer. | Browser pairing session controller behind `start_pairing` and `start_identity_recovery_pairing`. |
| `pairing-complete` | `{}` | `IdentityRecoveryPairing.tsx:86` marks done and calls `onRecovered`; `MobilePairingCard.tsx:306` marks transfer done. | `commands/pairing.rs:439,546` when the peer acknowledges a sent identity, or after a recovered identity is durably imported. | Browser pairing session controller; emit exactly once after durable success. |
| `pairing-error` | `{message:string}` | `IdentityRecoveryPairing.tsx:93` and `MobilePairingCard.tsx:327` leave the active flow and show an error/expired state. | `commands/pairing.rs:292,340,396,445,549` on WebSocket/session failure, 130-second timeout, invalid recovery payload, peer-reported failure, or recovery import failure. | Browser pairing session controller; convert transport, timeout, validation, and import failures to this terminal event. |
| `pairing-aborted` | `{reason:string}` | `IdentityRecoveryPairing.tsx:100` and `MobilePairingCard.tsx:316` leave the active flow and show “Pairing/Recovery stopped”. | `commands/pairing.rs:368` when a current session accepts a peer abort event. Local `cancel_pairing` invalidates silently. | Browser pairing session controller when a peer abort is received. Local cancel should continue to settle its command directly, matching Rust. |

### Deep-link family

| Event | Payload | Renderer listener and effect | Rust emitter and trigger | Owning browser PAL handler |
| --- | --- | --- | --- | --- |
| `deep-link-connect` | `string` (`ws://` or `wss://` relay URL) | `shared/deep-link.ts:137` treats the event as a wake-up and drains `take_pending_community_deep_link`; it does not consume the event payload. | `deep_link.rs:320` after validating `buzz://connect?relay=...`, focusing the app, and enqueuing the pending record. | Startup/location parser. Enqueue `{id,kind:"connect",relayUrl,code:null,policyReceipt:null,name:null}` first, then emit. |
| `deep-link-join` | `{relayUrl:string,code:string,policyReceipt:string|null}` | `shared/deep-link.ts:138` wakes the same pending-link drain; payload is not consumed. | `deep_link.rs:335` after validating relay and non-empty invite code and enqueuing the pending record. | Startup/location parser. Enqueue the equivalent `kind:"join"` pending record first, then emit. |
| `deep-link-add-community` | `{relayUrl:string,name?:string}` | `shared/deep-link.ts:139` wakes the same pending-link drain; payload is not consumed. | `deep_link.rs:351` after validating relay and enqueuing the pending record. | Startup/location parser. Enqueue the equivalent `kind:"add-community"` pending record first, then emit. |
| `deep-link-message` | `{channelId:string,messageId:string,threadRootId:string|null}` | `shared/deep-link.ts:163` passes the payload to router navigation. | `deep_link.rs:367` after `channel` and `id` are present and non-empty; optional `thread` becomes `threadRootId`. | Startup/location parser after router listener readiness; dispatch the validated payload directly. |
| `deep-link-nostr-bind` | `{challengeId:string,nonce:string,verificationCode:string,audience:"buzz:nostr-identity",action:"bind_nostr_identity",protocol:"buzz-nostr-identity",version:"1",origin:string,expiresAt:string,returnMode:"clipboard"|"browser_fragment_v1",callbackUrl?:string}` | `shared/deep-link.ts:171` opens the Nostr-bind consent flow. | `deep_link.rs:372` after field, protocol, origin, expiry-format, return-mode, and callback-origin validation. | Startup/location parser after consent listener readiness. Preserve Rust's validation, including HTTPS same-origin callback enforcement. |

### Native-only

| Event | Payload | Renderer listener and effect | Rust emitter and trigger | Why silence is safe in the browser |
| --- | --- | --- | --- | --- |
| `acp-install-output` | `{runtime_id:string,seq:number,line:string|null}` | `features/agents/lib/useInstallOutputLine.ts:72` filters by runtime, drops stale sequence numbers, clears on `line:null`, and shows the latest redacted line. | `commands/agent_discovery/install_report.rs:136,333,343` at attempt start and for throttled/redacted subprocess output. | ACP installation is native-only. The hook catches an unavailable event system and the install command's own settlement clears the line; browser capability gating must prevent starting an install. |
| `legacy-nest-migrated` | `null` | `features/communities/useNestNotifications.ts:31` shows a localStorage-deduped migration toast. | `lib.rs:481` at startup when legacy `~/.sprout` knowledge was copied. | No browser nest or filesystem migration exists. |
| `managed-agent-runtime-status` | `{pubkey:string,relayUrl:string,requestedRelayUrl?:string,localSetup:boolean,lifecycle:"starting"|"listening"|"waking"|"ready"|"failed"|"stopped",pid:number|null,error:string|null,logPath:string|null}` | `features/agents/lib/useAgentsDataRefresh.ts:31` invalidates runtime and legacy managed-agent queries. | `managed_agents/runtime_commands.rs:77` after accepted observer lifecycle changes, stale-process reconciliation, start, and stop. | A browser cannot own local harness processes. Gate local runtime controls. If a future remote-runtime PAL exposes equivalent asynchronous lifecycle commands, this event must be reclassified and synthesized. |
| `mesh-download-progress` | `{label:string,file:string|null,downloadedBytes:number|null,totalBytes:number|null,status:"preparing"|"downloading"|"done",done:boolean}` | `features/mesh-compute/hooks/useMeshDownloadProgress.ts:34` shows the latest non-done model download and clears on `done`. | `mesh_llm/progress.rs:56` for each mesh-llm `ModelDownloadProgress` output event. | Local model/mesh hosting is native-only. The hook degrades to no progress, and command settlement clears action-in-flight; browser capability gating must prevent mesh start. |
| `mouse-nav` | `"back"|"forward"` | `app/navigation/useBackForwardControls.ts:121` calls history back/forward. Listener registration is guarded by `isTauri()`. | `mouse_nav.rs:65,76` for macOS X1/X2 mouse-up or horizontal AppKit swipe. | Browsers supply DOM/history navigation inputs directly. |
| `native-notification-activated` | Linux: `DesktopNotificationTarget|null`; macOS: `null` wake-up followed by `take_pending_activations` | `features/notifications/lib/desktop.ts:257` dispatches the target to the app's DOM notification-action event. Registration is inside `isTauri()`. | `commands/notifications.rs:104` on Linux default-action click; `macos_notifications.rs:101` after queueing a macOS activation. | Browser `Notification.onclick` already dispatches the DOM action path; no Tauri event is registered outside Tauri. |
| `prevent-sleep-expired` | `null` | `features/agents/usePreventSleep.ts:88` sets `expired=true`, disabling the active assertion until observer activity clears it. | `prevent_sleep.rs:66` when the current native IOKit assertion reaches its one-hour inactivity cap. | The browser does not own the native sleep assertion. The browser `set_prevent_sleep_active` port must be a no-op/unsupported capability, so no expiry event is needed. |
| `repos-dir-error` | `string` | `features/communities/useNestNotifications.ts:25` shows a “Repos directory not applied” toast. | `commands/workspace.rs:159,203` when an override fails validation or its nest symlink cannot be applied. | Browser workspaces have no native repos directory/symlink. The PAL must not claim to apply `reposDir`. |
| `tray-action-available` | `null` | `app/useTrayMenu.ts:144` drains queued tray actions and navigates/opens create-channel. Registration and producer calls are guarded by `isTauri()`. | `tray_menu.rs:256,539` after a native tray action is queued or requeued. | A browser has no app tray; the entire hook is inactive. |

### Huddle family — deferred to Wave 5

| Event | Payload | Renderer listener and effect | Rust/renderer emitter and trigger | Wave-5 owner |
| --- | --- | --- | --- | --- |
| `huddle-state-changed` | `{phase:"idle"|"creating"|"connecting"|"connected"|"active"|"leaving",parent_channel_id:string|null,ephemeral_channel_id:string|null,huddle_thread_event_id:string|null,participants:string[],agent_pubkeys:string[],agent_voice_settings:Record<string,{enabled:boolean,voice_key:string}>,is_creator:boolean,tts_enabled:boolean,transcription_enabled:boolean,voice_input_mode:"push_to_talk"|"voice_activity"}` | Eight listeners: `app/useHuddlePresentation.ts:80,395`; `features/huddle/lib/useTtsSubscription.ts:228`; `features/huddle/components/HuddleRoomHeader.tsx:88`; `HuddleProfileControl.tsx:69`; `HuddleIndicator.tsx:196`; `HuddleBar.tsx:244`; `HuddleContext.tsx:466`. They route/show/tear down huddle UI, refresh roster/settings, gate TTS, and mirror backend ownership. | `huddle/state.rs:500`, called after phase, participant, TTS/transcription, voice-setting, and related observable state changes. | Wave-5 huddle lifecycle state machine. Emit a full snapshot after every observable mutation, not a partial delta. |
| `huddle-active-speakers` | `string[]` | `features/huddle/lib/useHuddleSpeakerActivity.ts:80` replaces remote active-speaker pubkeys. | `huddle/playout.rs:256` on each active-speaker timer tick. | Wave-5 browser audio playout/activity detector. |
| `huddle-speaker-levels` | `Record<string,number>` | `useHuddleSpeakerActivity.ts:43` replaces remote RMS levels. | `huddle/playout.rs:269,446` on level ticks and with `{}` when playout exits. | Wave-5 browser audio playout/activity detector; clear with `{}` on exit. |
| `huddle-tts-speaker-level` | `{pubkey:string|null,level:number}` | `useHuddleSpeakerActivity.ts:58` clamps the level and adds/removes local agent TTS activity. | `huddle/tts_speaker_cancellation.rs:58,78` at 50 ms TTS envelope frames and once with `{pubkey:null,level:0}` after activity ends. | Wave-5 browser TTS playback monitor. |
| `huddle-audio-disconnected` | `null` | `features/huddle/HuddleContext.tsx:907` starts a bounded audio-WebSocket reconnect loop while keeping media live. | `huddle/relay_api.rs:196` only when the audio relay pipeline exits unexpectedly, not during cancellation. | Wave-5 browser audio relay controller. |
| `huddle-companion-returned` | `null` | `app/useHuddlePresentation.ts:351` closes companion state, opens the main drawer, snapshots huddle state, and routes to its ephemeral channel. | `huddle/window.rs:34` after explicit companion close; `lib.rs:962` when the active native companion window closes. | Wave-5 browser presentation/window strategy. Emit only if browser companion presentation exists; otherwise keep the flow single-window and do not synthesize. |
| `ptt-state` | `boolean` | `features/huddle/lib/useHuddlePttState.ts:30` updates UI and plays cues; `features/huddle/lib/audioWorklet.ts:110` opens/closes worklet transmission in PTT mode. | `lib.rs:256,280` on native Ctrl+Space press and the non-superseded delayed release. | Wave-5 browser input/shortcut controller. It must preserve press/release ordering and the 200 ms release-tail behavior, or deliberately replace that contract. |
| `huddle-audio-command` | `{type:"request-state"}|{type:"set-muted",isMuted:boolean}|{type:"set-input-device",deviceId:string}|{type:"set-mic-gain",gain:number}|{type:"set-voice-input-mode",mode:"push_to_talk"|"voice_activity"}` | `features/huddle/HuddleContext.tsx:362` applies commands in the audio-owner renderer. | **No Rust emitter.** TypeScript emits it from the non-owner renderer (`HuddleContext.tsx:165,182,244,281,329`). | Wave-5 cross-context browser event bus/window strategy. |
| `huddle-audio-state` | `{isMuted:boolean,micConnected:boolean,audioDevices:Array<{deviceId:string,label:string}>,selectedDeviceId:string,micGain:number,voiceInputMode:"push_to_talk"|"voice_activity"}` | `features/huddle/HuddleContext.tsx:307` hydrates the non-owner renderer and stops its 500 ms request retry. | **No Rust emitter.** The audio-owner renderer emits snapshots (`HuddleContext.tsx:358,387`). | Wave-5 cross-context browser event bus/window strategy. Required if a separate companion context exists. |
| `huddle-audio-level` | `number` | `features/huddle/HuddleContext.tsx:875` mirrors microphone level into the non-owner renderer. | **No Rust emitter.** The audio-owner renderer emits on mic-level changes (`HuddleContext.tsx:867`). | Wave-5 cross-context browser event bus/window strategy. |

## Reconciliation gaps

- **Listeners with no Rust emitter:** `huddle-audio-command`,
  `huddle-audio-state`, and `huddle-audio-level`. This is intentional: they are
  TypeScript cross-window mirror events and are deferred with the huddle family.
- **Rust emitters with no renderer listener:** none.
- **Renderer `once()` subscriptions:** none. The only Rust-side `once()` in
  this flow consumes the reverse-direction `initial-render-ready` handshake
  described below.
- **Known-list additions:** `huddle-tts-speaker-level`,
  `huddle-audio-command`, `huddle-audio-state`, `huddle-audio-level`,
  `media-upload-progress`, `media-upload-phase`, `mesh-download-progress`, and
  `native-notification-activated`.
- **Reverse-direction event, not part of the 31:** the renderer emits
  `initial-render-ready` from `app/App.tsx:95`, and Rust subscribes once in
  `src-tauri/src/lib.rs:162`. It is not a Rust-emitted renderer subscription,
  but a browser bootstrap must not wait for the native Rust consumer.

## Machine-readable inventory

```json
[
  {"event":"acp-install-output","class":"native-only","payloadShape":"{runtime_id:string,seq:number,line:string|null}","listeners":["desktop/src/features/agents/lib/useInstallOutputLine.ts:72"],"owningPalHandler":"none"},
  {"event":"agents-data-changed","class":"pal-must-synthesize","payloadShape":"null","listeners":["desktop/src/features/agents/lib/useAgentsDataRefresh.ts:40"],"owningPalHandler":"reconcile_inbound_persona_event, confirm_agent_snapshot_import, confirm_team_snapshot_import"},
  {"event":"deep-link-add-community","class":"deep-link","payloadShape":"{relayUrl:string,name?:string}","listeners":["desktop/src/shared/deep-link.ts:139"],"owningPalHandler":"window.location deep-link bootstrap plus pending-community-link queue"},
  {"event":"deep-link-connect","class":"deep-link","payloadShape":"string (validated ws/wss relay URL)","listeners":["desktop/src/shared/deep-link.ts:137"],"owningPalHandler":"window.location deep-link bootstrap plus pending-community-link queue"},
  {"event":"deep-link-join","class":"deep-link","payloadShape":"{relayUrl:string,code:string,policyReceipt:string|null}","listeners":["desktop/src/shared/deep-link.ts:138"],"owningPalHandler":"window.location deep-link bootstrap plus pending-community-link queue"},
  {"event":"deep-link-message","class":"deep-link","payloadShape":"{channelId:string,messageId:string,threadRootId:string|null}","listeners":["desktop/src/shared/deep-link.ts:163"],"owningPalHandler":"window.location deep-link bootstrap after router readiness"},
  {"event":"deep-link-nostr-bind","class":"deep-link","payloadShape":"{challengeId:string,nonce:string,verificationCode:string,audience:string,action:string,protocol:string,version:string,origin:string,expiresAt:string,returnMode:string,callbackUrl?:string}","listeners":["desktop/src/shared/deep-link.ts:171"],"owningPalHandler":"window.location deep-link bootstrap after consent-listener readiness"},
  {"event":"huddle-active-speakers","class":"huddle","payloadShape":"string[]","listeners":["desktop/src/features/huddle/lib/useHuddleSpeakerActivity.ts:80"],"owningPalHandler":"Wave-5 browser audio playout/activity detector"},
  {"event":"huddle-audio-command","class":"huddle","payloadShape":"{type:'request-state'}|{type:'set-muted',isMuted:boolean}|{type:'set-input-device',deviceId:string}|{type:'set-mic-gain',gain:number}|{type:'set-voice-input-mode',mode:string}","listeners":["desktop/src/features/huddle/HuddleContext.tsx:362"],"owningPalHandler":"Wave-5 cross-context browser event bus/window strategy"},
  {"event":"huddle-audio-disconnected","class":"huddle","payloadShape":"null","listeners":["desktop/src/features/huddle/HuddleContext.tsx:907"],"owningPalHandler":"Wave-5 browser audio relay controller"},
  {"event":"huddle-audio-level","class":"huddle","payloadShape":"number","listeners":["desktop/src/features/huddle/HuddleContext.tsx:875"],"owningPalHandler":"Wave-5 cross-context browser event bus/window strategy"},
  {"event":"huddle-audio-state","class":"huddle","payloadShape":"{isMuted:boolean,micConnected:boolean,audioDevices:Array<{deviceId:string,label:string}>,selectedDeviceId:string,micGain:number,voiceInputMode:string}","listeners":["desktop/src/features/huddle/HuddleContext.tsx:307"],"owningPalHandler":"Wave-5 cross-context browser event bus/window strategy"},
  {"event":"huddle-companion-returned","class":"huddle","payloadShape":"null","listeners":["desktop/src/app/useHuddlePresentation.ts:351"],"owningPalHandler":"Wave-5 browser presentation/window strategy"},
  {"event":"huddle-speaker-levels","class":"huddle","payloadShape":"Record<string,number>","listeners":["desktop/src/features/huddle/lib/useHuddleSpeakerActivity.ts:43"],"owningPalHandler":"Wave-5 browser audio playout/activity detector"},
  {"event":"huddle-state-changed","class":"huddle","payloadShape":"full HuddleState JSON snapshot (snake_case fields)","listeners":["desktop/src/app/useHuddlePresentation.ts:80","desktop/src/app/useHuddlePresentation.ts:395","desktop/src/features/huddle/lib/useTtsSubscription.ts:228","desktop/src/features/huddle/components/HuddleRoomHeader.tsx:88","desktop/src/features/huddle/components/HuddleProfileControl.tsx:69","desktop/src/features/huddle/components/HuddleIndicator.tsx:196","desktop/src/features/huddle/components/HuddleBar.tsx:244","desktop/src/features/huddle/HuddleContext.tsx:466"],"owningPalHandler":"Wave-5 huddle lifecycle state machine"},
  {"event":"huddle-tts-speaker-level","class":"huddle","payloadShape":"{pubkey:string|null,level:number}","listeners":["desktop/src/features/huddle/lib/useHuddleSpeakerActivity.ts:58"],"owningPalHandler":"Wave-5 browser TTS playback monitor"},
  {"event":"legacy-nest-migrated","class":"native-only","payloadShape":"null","listeners":["desktop/src/features/communities/useNestNotifications.ts:31"],"owningPalHandler":"none"},
  {"event":"managed-agent-runtime-status","class":"native-only","payloadShape":"{pubkey:string,relayUrl:string,requestedRelayUrl?:string,localSetup:boolean,lifecycle:string,pid:number|null,error:string|null,logPath:string|null}","listeners":["desktop/src/features/agents/lib/useAgentsDataRefresh.ts:31"],"owningPalHandler":"none"},
  {"event":"media-upload-phase","class":"pal-must-synthesize","payloadShape":"{id:string,phase:'preparing'|'processing-video'|'converting-image'|'uploading'|'finishing'}","listeners":["desktop/src/features/messages/lib/backgroundMediaUploadStore.ts:132"],"owningPalHandler":"browser media upload handlers receiving progressId"},
  {"event":"media-upload-progress","class":"pal-must-synthesize","payloadShape":"{id:string,sent:number,total:number}","listeners":["desktop/src/features/messages/lib/useMediaUpload.ts:195","desktop/src/features/messages/lib/backgroundMediaUploadStore.ts:106"],"owningPalHandler":"browser media upload handlers receiving progressId"},
  {"event":"mesh-download-progress","class":"native-only","payloadShape":"{label:string,file:string|null,downloadedBytes:number|null,totalBytes:number|null,status:'preparing'|'downloading'|'done',done:boolean}","listeners":["desktop/src/features/mesh-compute/hooks/useMeshDownloadProgress.ts:34"],"owningPalHandler":"none"},
  {"event":"mouse-nav","class":"native-only","payloadShape":"'back'|'forward'","listeners":["desktop/src/app/navigation/useBackForwardControls.ts:121"],"owningPalHandler":"none"},
  {"event":"native-notification-activated","class":"native-only","payloadShape":"DesktopNotificationTarget|null (Linux) or null wake-up (macOS)","listeners":["desktop/src/features/notifications/lib/desktop.ts:257"],"owningPalHandler":"none"},
  {"event":"pairing-aborted","class":"pal-must-synthesize","payloadShape":"{reason:string}","listeners":["desktop/src/features/onboarding/ui/IdentityRecoveryPairing.tsx:100","desktop/src/features/settings/ui/MobilePairingCard.tsx:316"],"owningPalHandler":"browser NIP-AB pairing session controller"},
  {"event":"pairing-complete","class":"pal-must-synthesize","payloadShape":"{}","listeners":["desktop/src/features/onboarding/ui/IdentityRecoveryPairing.tsx:86","desktop/src/features/settings/ui/MobilePairingCard.tsx:306"],"owningPalHandler":"browser NIP-AB pairing session controller"},
  {"event":"pairing-error","class":"pal-must-synthesize","payloadShape":"{message:string}","listeners":["desktop/src/features/onboarding/ui/IdentityRecoveryPairing.tsx:93","desktop/src/features/settings/ui/MobilePairingCard.tsx:327"],"owningPalHandler":"browser NIP-AB pairing session controller"},
  {"event":"pairing-sas-received","class":"pal-must-synthesize","payloadShape":"{sas:string}","listeners":["desktop/src/features/onboarding/ui/IdentityRecoveryPairing.tsx:80","desktop/src/features/settings/ui/MobilePairingCard.tsx:296"],"owningPalHandler":"browser NIP-AB pairing session controller"},
  {"event":"prevent-sleep-expired","class":"native-only","payloadShape":"null","listeners":["desktop/src/features/agents/usePreventSleep.ts:88"],"owningPalHandler":"none"},
  {"event":"ptt-state","class":"huddle","payloadShape":"boolean","listeners":["desktop/src/features/huddle/lib/useHuddlePttState.ts:30","desktop/src/features/huddle/lib/audioWorklet.ts:110"],"owningPalHandler":"Wave-5 browser input/shortcut controller"},
  {"event":"repos-dir-error","class":"native-only","payloadShape":"string","listeners":["desktop/src/features/communities/useNestNotifications.ts:25"],"owningPalHandler":"none"},
  {"event":"tray-action-available","class":"native-only","payloadShape":"null","listeners":["desktop/src/app/useTrayMenu.ts:144"],"owningPalHandler":"none"}
]
```
