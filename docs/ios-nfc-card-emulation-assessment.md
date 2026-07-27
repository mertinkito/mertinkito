# iOS NFC Card Vault — Technical Assessment & Implementation Guide

**Goal evaluated:** an "Apple Pay‑style" app that lets a user scan an arbitrary
NFC card (hotel key, office badge, smart‑lock card) and later have the
iPhone *emulate* that card against a third‑party reader.

**Bottom line up front:** reading arbitrary NFC cards with CoreNFC is fully
supported and reliable. Emulating an arbitrary third‑party NFC card from a
non‑Apple app is **not possible on iOS today**, by deliberate design, and no
public entitlement changes that. Any product plan has to be built around
that constraint rather than around a hope that entitlements will unlock it.
Sections 3–5 lay out what to build instead.

---

## 1. CoreNFC Limitations & Feasibility

### 1.1 What CoreNFC actually is

CoreNFC is a **reader‑only** framework. The iPhone's NFC controller (NXP/ST
chip depending on model) has two logical modes that matter here:

| Mode | Who controls it | Public API? |
|---|---|---|
| **Reader/Writer mode** (phone reads/writes a passive tag or emulated card) | Third‑party apps, via CoreNFC | Yes — `NFCTagReaderSession`, `NFCNDEFReaderSession` |
| **Card Emulation mode / HCE** (phone *acts as* a contactless card presenting to an external reader) | Apple system processes only (Wallet, Secure Element applets) | **No.** There is no `HostApduService`‑equivalent public API on iOS. |

This is the single fact that determines everything else in this document.
Android exposes `HostApduService` / HCE to any app with the
`android.permission.NFC` + a manifest service declaration. iOS has never
exposed the symmetric capability, and Apple has not signaled any plan to.
The NFC controller's card‑emulation path is wired directly to the **Secure
Element (SE)**, which is provisioned and locked by Apple; general-purpose
app code cannot register an applet into it, and cannot drive the antenna in
emulation mode from user-space.

### 1.2 What's possible without special entitlements

With the standard `com.apple.developer.nfc.readersession.formats`
entitlement (free, self-service in your provisioning profile) and iOS 13+:

- **`NFCNDEFReaderSession`** — read (and, since iOS 13, write/lock) NDEF
  messages on Type 1–5 tags. Highest-level API, works in the background for
  "scan to open" style triggers, but only sees NDEF-formatted payloads.
- **`NFCTagReaderSession`** — lower-level, polls for a specific technology
  and gives you the tag object to talk to directly:
  - `.iso14443` — ISO 14443‑A/B cards: MIFARE Classic/Ultralight/DESFire,
    most access-control and transit cards, most hotel key cards. You get
    the **UID**, ATQA/SAK, historical bytes, and can send raw APDUs
    (`NFCISO7816Tag.sendCommand`) or MIFARE commands
    (`NFCMiFareTag.sendMiFareCommand`).
  - `.iso15693` — vicinity cards (some access badges, retail tags).
  - `.felica` — FeliCa (common in Japan/transit).
  - `.iso18092` — NFC‑F / peer‑to‑peer.
- **UID retrieval**: yes, via `tag.identifier` (a `Data` blob) regardless of
  which of the above technologies matched. This is usually enough to
  *identify* a card but is **not** enough to *clone* it if the backend
  system checks anything beyond a static UID (most modern access-control
  and hotel-lock systems do — see §1.4).
- **Sector/key‑based reads** (MIFARE Classic sector auth with Crypto‑1,
  MIFARE DESFire with 3DES/AES): CoreNFC lets you shuttle the raw APDU/MIFARE
  commands, but you must implement the authentication and crypto yourself;
  CoreNFC does not include a Crypto‑1 or DESFire crypto library. Whether
  this works at all depends on whether the card uses factory-default keys
  or a real, hotel-specific key you don't have.

### 1.3 What requires special Apple entitlements (and is not generally available)

- **`com.apple.developer.nfc.readersession.formats` with `TAG` for
  government IDs / eSE-backed tags** — some sub-capabilities (e.g. reading
  ISO 7816 tags that need extended polling) require values Apple grants
  case-by-case.
- **VAS (Value Added Services)** — Apple's protocol for reading
  loyalty/coupon passes from Wallet at retail readers. Requires signing
  Apple's *Value Added Services Programming Guide* agreement; it's a
  reader-side integration for merchants, not a way for your app to emit an
  arbitrary card.
- **`com.apple.developer.secure-element-credential`** — the entitlement
  behind Car Key, Home Key, Hotel Key (Room Key) and Transit Pass in
  Wallet. This is **restricted to Apple-vetted partners** (a hotel chain, a
  lock manufacturer such as ASSA ABLOY/dormakaba, a transit authority). It
  requires a business agreement with Apple, hardware certification of the
  lock/reader against Apple's spec, and provisioning a dedicated SE applet
  that Apple controls. It is not obtainable by an indie or enterprise app
  developer for "any card a user happens to scan."
- **Employee Badge in Wallet** (WWDC 2023) — same story: requires your
  building's access-control vendor (HID, ASSA ABLOY, etc.) to integrate
  with Apple directly. Your app cannot piggyback on this for an arbitrary
  employer's badge system.

### 1.4 Why "just clone the UID" usually doesn't work anyway

Even if iOS allowed raw HCE, most real deployments defeat naive cloning:

- MIFARE Classic sector data is protected by per-sector keys (often
  site-specific, not the default `FFFFFFFFFFFF`).
- MIFARE DESFire / iCLASS SE / SEOS cards use mutual authentication with
  diversified keys per card — reading the UID gives you an identifier, not
  a working credential.
- Modern hotel PMS/lock systems (Assa Abloy Vostio, dormakaba, Salto) often
  rotate a lock-specific session key per stay, unrelated to the physical
  card's UID.

So the honest framing for the product is: **UID-only cloning may work
against legacy/low-security deployments (some old MIFARE Classic office
door systems) but must never be marketed as a general "clone any card"
capability** — both because it will silently fail against modern locks, and
because presenting it that way invites misuse against systems the user
doesn't own/administer. Scope the feature to *the user's own* credentials
and say so in UI copy and store review notes.

---

## 2. NFC Reading Implementation

Below is a SwiftUI-friendly reader built on `NFCTagReaderSession`, since it
gives access to UID + raw ISO14443/MIFARE commands (the superset you need
for a "scan my card" flow). Falls back gracefully if the tag only supports
NDEF.

```swift
// NFCCardReader.swift
import CoreNFC
import Combine

struct ScannedCard: Identifiable, Equatable {
    let id = UUID()
    let uid: Data
    let technology: String
    let historicalBytes: Data?
    let ndefPayload: Data?

    var uidHex: String { uid.map { String(format: "%02X", $0) }.joined() }
}

@MainActor
final class NFCCardReader: NSObject, ObservableObject {
    @Published var lastScan: ScannedCard?
    @Published var errorMessage: String?
    @Published var isScanning = false

    private var session: NFCTagReaderSession?

    func beginScan() {
        guard NFCTagReaderSession.readingAvailable else {
            errorMessage = "This device does not support NFC tag reading."
            return
        }
        session = NFCTagReaderSession(
            pollingOption: [.iso14443, .iso15693, .iso18092],
            delegate: self,
            queue: .main
        )
        session?.alertMessage = "Hold your iPhone near the card."
        session?.begin()
        isScanning = true
    }
}

extension NFCCardReader: NFCTagReaderSessionDelegate {
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Task { @MainActor in
            self.isScanning = false
            if let nfcError = error as? NFCReaderError,
               nfcError.code != .readerSessionInvalidationErrorUserCanceled {
                self.errorMessage = nfcError.localizedDescription
            }
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else { return }

        session.connect(to: tag) { [weak self] error in
            if let error {
                session.invalidate(errorMessage: "Connection failed: \(error.localizedDescription)")
                return
            }

            switch tag {
            case let .iso7816(iso7816Tag):
                self?.readISO7816(iso7816Tag, session: session)
            case let .miFare(miFareTag):
                self?.readMiFare(miFareTag, session: session)
            case let .iso15693(iso15693Tag):
                self?.readISO15693(iso15693Tag, session: session)
            case let .feliCa(feliCaTag):
                self?.readFeliCa(feliCaTag, session: session)
            @unknown default:
                session.invalidate(errorMessage: "Unsupported tag type.")
            }
        }
    }

    private func readISO7816(_ tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        let scan = ScannedCard(
            uid: tag.identifier,
            technology: "ISO 7816 (ISO14443-A)",
            historicalBytes: tag.historicalBytes,
            ndefPayload: nil
        )
        finish(scan, session: session)
    }

    private func readMiFare(_ tag: NFCMiFareTag, session: NFCTagReaderSession) {
        // Example: read block 0 (manufacturer block, always readable) via raw command.
        let readBlockZero: [UInt8] = [0x30, 0x00] // MIFARE "READ" command, block 0
        tag.sendMiFareCommand(commandPacket: Data(readBlockZero)) { [weak self] data, error in
            let scan = ScannedCard(
                uid: tag.identifier,
                technology: "MIFARE (\(tag.mifareFamily))",
                historicalBytes: tag.historicalBytes,
                ndefPayload: error == nil ? data : nil
            )
            self?.finish(scan, session: session)
        }
    }

    private func readISO15693(_ tag: NFCISO15693Tag, session: NFCTagReaderSession) {
        let scan = ScannedCard(uid: tag.identifier, technology: "ISO 15693", historicalBytes: nil, ndefPayload: nil)
        finish(scan, session: session)
    }

    private func readFeliCa(_ tag: NFCFeliCaTag, session: NFCTagReaderSession) {
        let scan = ScannedCard(uid: tag.currentIDm, technology: "FeliCa", historicalBytes: nil, ndefPayload: nil)
        finish(scan, session: session)
    }

    private func finish(_ scan: ScannedCard, session: NFCTagReaderSession) {
        Task { @MainActor in
            self.lastScan = scan
            self.isScanning = false
        }
        session.alertMessage = "Card scanned successfully."
        session.invalidate()
    }
}
```

SwiftUI view:

```swift
struct ScanCardView: View {
    @StateObject private var reader = NFCCardReader()

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "wave.3.right.circle")
                .font(.system(size: 64))
                .symbolEffect(.variableColor.iterative, isActive: reader.isScanning)

            if let scan = reader.lastScan {
                VStack(alignment: .leading) {
                    Text("UID: \(scan.uidHex)").font(.headline)
                    Text(scan.technology).font(.subheadline).foregroundStyle(.secondary)
                }
            }

            Button("Scan Card") { reader.beginScan() }
                .buttonStyle(.borderedProminent)
        }
        .alert("NFC Error", isPresented: .constant(reader.errorMessage != nil)) {
            Button("OK") { reader.errorMessage = nil }
        } message: {
            Text(reader.errorMessage ?? "")
        }
    }
}
```

`Info.plist` needs `NFCReaderUsageDescription`, and for ISO 7816 AID-based
polling (optional) `com.apple.developer.nfc.readersession.iso7816.select-identifiers`.

---

## 3. Card Emulation Workarounds (given §1)

Since arbitrary HCE is off the table, the realistic architecture is a
**tiered fallback**, from "fully native, but only for supported card
types" down to "requires companion hardware":

### Tier 1 — Apple Wallet integration (best UX, narrowest coverage)
For card types Apple explicitly supports, integrate with the *actual*
program instead of reinventing it:
- **Hotel Key (Room Key)** — if the property's PMS/lock vendor already has
  an Apple Wallet integration, your app's job is just to deep-link into
  that provisioning flow (`PKAddSecureElementPassViewController` /
  the hotel's own SDK), not to build your own emulation.
- **Employee Badge** — same pattern via the building's access-control
  vendor if they support Wallet.
- This tier requires zero custom RF work and gets full double-tap-side-
  button / Apple Pay-style UX for free, but only covers cards whose issuer
  has an Apple partnership. It cannot be generalized to "any card."

### Tier 2 — BLE-to-NFC bridge hardware (general coverage, needs a companion device)
Do the RF emulation on a small external device instead of the iPhone's own
NFC radio, and use the phone only as the UI/keychain/orchestrator:
- A companion dongle (custom PCB around an NXP PN532 in target/card
  emulation mode, or a repurposed Proxmark/Chameleon/Flipper-class chip)
  holds the actual emulation logic.
- iPhone talks to it over **Core Bluetooth** (BLE), sends "emulate card
  with these keys/UID," dongle presents itself to the real-world reader.
- This is the same architectural pattern real product categories already
  use for "digital key fob" replacements. It sidesteps the iOS HCE wall
  entirely because the RF transmission is not happening through Apple's
  NFC controller.
- Trade-offs: extra hardware to carry, BOM/manufacturing cost, and MFi
  certification is *not* required for BLE-only accessories (MFi is
  primarily for Lightning/authentication coprocessor accesses), but you do
  need your own RF hardware compliance (FCC/CE) for the dongle.

### Tier 3 — Reader-side software integration (no RF emulation at all)
For access-control systems you control or partner with, skip NFC entirely:
issue the credential over BLE/Wi-Fi directly to the reader's backend (many
modern access-control readers, e.g. via Wiegand-over-IP controllers,
support mobile credential SDKs — HID Mobile Access, Salto JustIN Mobile,
dormakaba Mobile Access). This requires the *reader infrastructure* to
support it, so it doesn't help with "arbitrary hotel key" but is the right
answer if you're building for a specific enterprise customer's own doors.

### What does *not* work
- There is no jailbreak-free way to register a background HCE service.
- MFi enrollment does not grant NFC HCE; it governs
  Lightning/Bluetooth accessory authentication, unrelated to the SE/NFC
  emulation path.
- Private/undocumented API use (`AppleNFC`/`SecureElement` private
  frameworks some jailbreak tweaks touch) will fail App Review and is out
  of scope for any App Store-distributed product.

**Recommendation:** ship Tier 1 for the subset of cards where it applies
(marketing hook: "add your hotel key the same way Marriott/Hyatt already
let you"), and build Tier 2 as the actual general-purpose product — the
BLE dongle *is* the product, the app is its companion. Do not promise
"scan any card, emulate with just your phone" in store copy; it's not
achievable and will draw both technical bug reports and App Review/legal
scrutiny.

---

## 4. App Architecture & UI/UX

### 4.1 Architecture: MVVM + Combine, thin domain layer

```
CardVaultApp/
├── App/
│   └── CardVaultApp.swift               // @main, DI root
├── Domain/
│   ├── Models/ (StoredCard, CardTechnology, EmulationTarget)
│   ├── Services/
│   │   ├── NFCReadingService (protocol) → CoreNFCReadingService
│   │   ├── CardEmulationService (protocol) → BLEBridgeEmulationService | WalletPassEmulationService
│   │   ├── SecureVaultService (protocol) → KeychainVaultService
│   │   └── BiometricAuthService (protocol) → LocalAuthService
│   └── UseCases/ (ScanCardUseCase, SaveCardUseCase, EmulateCardUseCase)
├── Data/
│   ├── Keychain/ (KeychainStore, SecureEnclaveKeyManager)
│   └── BLE/ (BridgeDeviceManager: CoreBluetooth central)
├── Presentation/
│   ├── Wallet/ (WalletView, WalletViewModel)          // card carousel, Apple-Pay-like
│   ├── ScanCard/ (ScanCardView, ScanCardViewModel)
│   ├── CardDetail/ (CardDetailView, CardDetailViewModel)
│   └── Emulate/ (EmulateSheetView, EmulateViewModel)
└── Shared/ (DesignSystem, Extensions)
```

Why MVVM over TCA here: the domain logic is a handful of largely
independent, side-effect-heavy flows (NFC session lifecycle, BLE
connection lifecycle, Keychain/biometric gate) rather than a single deeply
nested state tree with heavy time-travel/undo requirements — TCA's
ceremony (Reducers, Effects, Store composition) buys less than it costs
for a single-screen-at-a-time wallet app. Combine/`@Observable` +
protocol-based services already get you testability (mock each service
protocol) without the extra dependency. Reach for TCA instead if the roadmap
adds cross-cutting state sharing (e.g. widget + app + Watch app all reading
the same live emulation state) — that's where its unidirectional store
pays for itself.

Each `Service` is a protocol so `EmulateViewModel` never knows whether the
concrete implementation is a Tier 1 Wallet pass or a Tier 2 BLE bridge —
`EmulationTarget` on the model decides which implementation gets injected.

### 4.2 UI/UX flow

**Activation:** the side-button double-click is a **private, Apple-Pay-only
affordance** — there is no public API to hook a third-party app into it.
Realistic alternatives that mimic the feel:
- A **Home Screen widget** / **Lock Screen widget** (`WidgetKit`,
  interactive since iOS 17) showing the "default" card with a tap target
  that opens straight into `EmulateSheetView`.
- **StandBy** mode card view for nightstand/desk use.
- **App Intents / Shortcuts**, so the card can be triggered via the
  **Action Button** on Pro models, back-tap, or a Shortcuts automation.
- Background **NFC tag detection** (`NFCNDEFReaderSession` with
  `.detectorAlertMessage`, plus `App Clips` NFC triggers) so tapping the
  phone *against a reader* can wake the app the way Apple Pay wakes the
  system UI — but note the app still has to present the credential via the
  Tier 1/2 mechanism above, not raw HCE.

**Core screens:**
1. **Wallet (home)** — horizontally scrolling card carousel styled like
   Apple Wallet (`ScrollView(.horizontal)` + `.scrollTargetBehavior(.paging)`,
   parallax/tilt on drag), each card showing name, icon by technology
   (hotel/office/lock), and a small "last used" timestamp.
2. **Scan Card** — full-screen NFC prompt (reuses system `NFCTagReaderSession`
   sheet chrome), success animation, then a naming/tagging step
   (icon, color, category) before it's written to the vault.
3. **Card Detail** — shows UID (masked by default, biometric-gated reveal),
   technology, date added, "Emulate" primary button, "Delete" destructive
   action requiring Face ID.
4. **Emulate Sheet** — modal, Face ID gate → shows a live status
   ("Ready — hold near reader" / "Connected to Bridge" / "Presented") with
   haptic feedback on success, auto-dismiss after a timeout, matching Apple
   Pay's "Done ✓" checkmark beat.
5. **Settings** — bridge device pairing (Tier 2), default card selection,
   biometric requirement toggle, export/delete-all (GDPR-style data
   controls).

---

## 5. Security & Privacy

Treat every stored card as a credential, not just data — UID plus any
sector keys/derived secrets should get the same handling you'd give a
private key.

### 5.1 Storage model

- **Never store raw card secrets in `UserDefaults`, files, or plain
  `NSData` blobs.** Everything sensitive lives in the **Keychain**.
- Use a two-layer scheme:
  1. A **Secure Enclave-backed P‑256 key** (`kSecAttrTokenIDSecureEnclave`)
     acts as a key-wrapping key. It never leaves the SE and can require
     biometry per use.
  2. The actual card payload (UID, sector keys, derived credential blob)
     is encrypted with a symmetric key (AES-GCM via `CryptoKit`) that is
     itself wrapped by the SE key, and the wrapped blob is what's stored in
     the Keychain item's `kSecValueData`.
- Keychain item access control:

```swift
import Security
import LocalAuthentication

func makeAccessControl() -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.biometryCurrentSet, .privateKeyUsage],
        &error
    ) else {
        fatalError("SecAccessControl error: \(error!.takeRetainedValue())")
    }
    return access
}

func storeCardSecret(_ wrappedData: Data, account: String) throws {
    let access = makeAccessControl()
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.yourapp.cardvault",
        kSecAttrAccount as String: account,
        kSecValueData as String: wrappedData,
        kSecAttrAccessControl as String: access,
        kSecUseDataProtectionKeychain as String: true
    ]
    SecItemDelete(query as CFDictionary) // replace if re-saving
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
}
```

  - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — never synced to
    iCloud Keychain, never available before first unlock, never restorable
    to another device. Card secrets should not silently migrate to a new
    phone; re-provisioning should require the user to re-scan or
    re-authorize with the issuing system.
  - `.biometryCurrentSet` — invalidates the item if the enrolled biometrics
    change (new fingerprint/face added), forcing re-auth; prevents someone
    who added their own face to a stolen, unlocked phone from silently
    inheriting access.

- **Biometric gate at point of use**, not just at storage time — require
  Face ID/Touch ID immediately before every emulation attempt and before
  revealing raw UID/keys in Card Detail, using `LAContext` with
  `.deviceOwnerAuthenticationWithBiometrics` (fall back to passcode only if
  you explicitly want that, otherwise use `.biometryAny` without fallback
  for stronger guarantees).

### 5.2 Additional practices

- **App Attest / DeviceCheck** for the BLE bridge pairing handshake, so a
  bridge device only accepts commands from a legitimate, unmodified copy
  of your app instance.
- **Encrypt Keychain data at rest with per-install keys**, never a
  hardcoded or bundled key — derive nothing from a static app secret.
- **No verbose logging of UIDs/keys** — scrub `os_log`/crash reports; a UID
  in a crash log is still a credential fragment.
- **Local-only by default**: don't sync card vault contents to a backend
  unless the user explicitly opts into multi-device sync, and if you do,
  use end-to-end encryption where the server never sees plaintext keys
  (e.g., encrypt client-side with a key derived from the user's device
  passcode/biometric-gated Secure Enclave key, not a server-held key).
- **Data minimization / consent copy**: since this touches physical
  security systems, be explicit in onboarding that users may only store
  cards they are authorized to possess/duplicate, and keep an audit log
  (locally, Keychain-protected) of scan and emulation events the user can
  review and export — this materially helps both trust and any eventual
  App Review / enterprise security review conversation.

---

## Summary Verdict

| Capability | Status on iOS |
|---|---|
| Read UID / NDEF / raw APDU from arbitrary NFC card | ✅ Fully supported, public API (§2) |
| Emulate arbitrary third-party NFC card via iPhone's own NFC radio | ❌ Not possible, no public API, SE is Apple-locked |
| Emulate Apple-partnered card types (hotel/home/car key, employee badge) | ✅ Via Wallet, but only if the issuer has an Apple partnership |
| Emulate arbitrary card via companion BLE hardware | ✅ Architecturally sound, requires building/certifying a dongle |
| "Double-click side button" style activation for your own app | ❌ Private to Apple Pay; use widgets/Action Button/Shortcuts instead |

Plan the product around the BLE-bridge tier for general coverage, use the
Wallet integration tier where the issuer already supports it, and be
explicit in product messaging that emulation is bounded by these platform
constraints — not a rough edge to be smoothed over in v2.
