# Apple Wallet Digital Room Key — PassKit Implementation Guide

**Continuation of** `docs/ios-nfc-card-emulation-assessment.md`. That
document established that raw NFC card emulation isn't available to
third-party apps. This one goes deeper on the *actual* Apple-sanctioned
path — Wallet's secure-element "Key" pass type — and is honest about where
self-serve engineering ends and an Apple business/partnership process
begins.

**Read this first, it changes the whole roadmap:** there are two
completely different things both called "adding an NFC pass to Wallet,"
and only one of them can unlock a real door reader.

| | **VAS-enabled standard `PKPass`** | **Secure Element "Key" pass (Hotel Key / Home Key / Car Key)** |
|---|---|---|
| Who can build it | Any developer, self-serve, today | Only Apple-approved partners (hotel/PMS/lock vendor, home accessory maker, automaker) |
| How it's provisioned | Standard pass signing + PassKit Web Service | `PKAddSecureElementPassViewController`, credential issued by Apple's partner backend |
| Where the credential lives | Encrypted blob inside the pass, read by an NFC terminal that speaks Apple's **VAS** protocol | A dedicated applet inside the iPhone's **Secure Element**, provisioned via Apple's infrastructure |
| Works with Face ID off / phone dead (Power Reserve) | No | Yes |
| Compatible with a typical hotel door lock (MIFARE/iCLASS reader) | **No** — VAS is a retail/loyalty protocol; door locks don't speak it | Yes, if the lock vendor has integrated Apple's SE protocol |
| Realistic use for "unlock a door" | Not viable as the unlock mechanism | The actual mechanism Marriott/Hyatt-style Wallet room keys use |

If your goal is "tap iPhone on the existing door reader, door unlocks,"
the VAS pass is the wrong tool even though it's the one you can build
without Apple's involvement — it will not talk to the lock. The
sections below cover both, but §1–2 flag clearly which parts are
self-serve and which require partnership.

---

## 1. PassKit & Apple Wallet Integration

### 1.1 Standard `PKPass` signing (self-serve — works today for non-lock use cases)

Required from the Apple Developer portal (no special approval, any paid
account):
1. **Pass Type ID** — Certificates, Identifiers & Profiles → Identifiers →
   register `pass.com.yourcompany.roomkey`.
2. **Pass Type ID Certificate** — generate a CSR locally, upload it,
   download the signed cert, export as `.p12` with its private key.
3. **Apple WWDR intermediate certificate** (currently G4) — download from
   Apple PKI, needed alongside your cert to build the signature chain.

Pass structure (`.pkpass` = a zip):

```
roomkey.pkpass/
├── pass.json
├── manifest.json      // SHA-1/SHA-256 of every other file
├── signature           // PKCS#7 detached signature over manifest.json
├── icon.png / icon@2x.png / icon@3x.png
├── logo.png / logo@2x.png
└── strip.png (optional)
```

`pass.json`, using the `nfc` dictionary (Value Added Services):

```json
{
  "formatVersion": 1,
  "passTypeIdentifier": "pass.com.yourcompany.roomkey",
  "serialNumber": "res-8841-room412",
  "teamIdentifier": "ABCDE12345",
  "organizationName": "Your Hotel Co",
  "description": "Room 412 Key",
  "generic": {
    "headerFields": [{ "key": "room", "label": "ROOM", "value": "412" }],
    "primaryFields": [{ "key": "guest", "label": "GUEST", "value": "J. Smith" }],
    "secondaryFields": [
      { "key": "checkin", "label": "CHECK-IN", "value": "2026-07-27" },
      { "key": "checkout", "label": "CHECK-OUT", "value": "2026-07-30" }
    ]
  },
  "nfc": {
    "message": "urn:yourhotel:key:res-8841",
    "encryptionPublicKey": "<base64 P-256 public key you generated>",
    "requiresAuthentication": true
  },
  "webServiceURL": "https://api.yourhotel.com/passkit/",
  "authenticationToken": "<32+ char random token per pass>"
}
```

Notes:
- `requiresAuthentication` (added in a later PassKit revision) gates the
  NFC read behind Face ID/Touch ID — verify availability against the
  current *PassKit Package Format Reference* for your minimum iOS target.
- `encryptionPublicKey` is used for **VAS**, Apple's read protocol for
  merchant/loyalty terminals. **A merchant's VAS reader is a different
  product category than an access-control door reader** — VAS is what
  lets a retail terminal silently read a loyalty identifier off a pass in
  someone's pocket; it is not spoken by MIFARE/iCLASS/Wiegand-style door
  locks. Don't build this expecting it to unlock anything; use it only if
  you're also building/controlling the reader terminal and it explicitly
  implements Apple's VAS spec (requires signing the *Value Added Services
  Programming Guide* agreement with Apple separately).

Signing (`openssl`, illustrating the manifest/signature step every pass
generator — Node `passkit-generator`, Python `wallet`, PassKit-as-a-service
vendors — performs under the hood):

```bash
# One-time: convert exported certs to PEM
openssl pkcs12 -in passcertificate.p12 -clcerts -nokeys -out passcertificate.pem -passin pass:yourpassword
openssl pkcs12 -in passcertificate.p12 -nocerts -out passkey.pem -passin pass:yourpassword -passout pass:yourpassword

# Per pass: hash every file into manifest.json (your build script does this), then:
openssl smime -binary -sign \
  -signer passcertificate.pem \
  -inkey passkey.pem -passin pass:yourpassword \
  -certfile wwdr.pem \
  -in manifest.json \
  -out signature -outform DER

zip -r roomkey.pkpass pass.json manifest.json signature icon.png icon@2x.png logo.png logo@2x.png
```

**Push updates**: implement the 5 PassKit Web Service endpoints
(register device, unregister device, list updated serial numbers for a
device, fetch a pass, log errors) and send an APNs push using the pass's
push token whenever backend state changes (e.g., extended checkout date),
so Wallet re-fetches the updated pass.

### 1.2 Secure Element "Key" pass — entitlements & partnership (not self-serve)

There is **no toggle in the Developer Portal** that turns a pass into a
Hotel Key / Home Key / Car Key-style Secure Element credential. Each is a
distinct Apple partner program:

- **Hotel Key (Room Key)** — Apple integrates at the **lock/PMS vendor**
  level (ASSA ABLOY Vostio, dormakaba, Salto, etc.), not per hotel brand
  app. If your app is for a property using one of these vendors' existing
  Apple integration, your engineering work is a deep-link/handoff into
  that vendor's provisioning SDK — you are not standing up your own SE
  provisioning server. If your property's lock vendor has no such
  integration yet, the prerequisite is a business relationship between
  that vendor and Apple, not app code.
- **Home Key** — governed by **Aliro**, the cross-platform accessory
  unlock standard Apple co-developed (via the Connectivity Standards
  Alliance) so Home Key-class credentials work across ecosystems. Building
  a *lock/accessory* that supports it means joining the "Works with Apple
  Home" + Aliro certification program and implementing the standard's
  cryptographic handshake in your lock's firmware.
- **Car Key** — built on the **CCC (Car Connectivity Consortium) Digital
  Key** specification (release 2/3), requires automaker-level
  participation in Apple's Car Key program.

For all three, Apple issues the necessary entitlement and provisioning
credentials directly to the approved partner after an NDA and technical
certification process; there's no public entitlement string you add to
your `.entitlements` file speculatively. If you're evaluating this path,
the actionable first step is contacting Apple through
developer.apple.com's partner-program channels (or your existing Apple
developer relations contact) to scope which program applies, **before**
committing engineering time to `PKAddSecureElementPassViewController`
integration — the API is unusable without a partner-issued credential
backend regardless of how correctly you call it.

Schematic (illustrative — exact class/property names have shifted across
iOS releases as Apple folded Car Key/Home Key/Hotel Key into a common
Secure Element pass API; confirm current signatures in Apple's PassKit
documentation once you have partner access):

```swift
import PassKit

func presentSecureElementProvisioning(from viewController: UIViewController) {
    let configuration = PKAddSecureElementPassConfiguration()
    configuration.primaryAccountIdentifier = "res-8841-room412"
    configuration.primaryAccountNumberSuffix = "0412"
    configuration.pairingOption = .other // exact enum case depends on SDK version

    guard let addPassVC = PKAddSecureElementPassViewController(
        configuration: configuration,
        delegate: someDelegate
    ) else { return }
    viewController.present(addPassVC, animated: true)
}
```

The `PKAddSecureElementPassViewControllerDelegate` callbacks hand you an
opaque request that your backend forwards to **Apple's partner
provisioning service** (using credentials Apple issued to your
organization specifically); Apple's service returns an encrypted
credential blob that gets written into the phone's Secure Element. Your
server never sees or generates the raw SE credential material itself — it
brokers Apple's protocol.

---

## 2. NFC Card Reading to Pass Data

The scanning step is identical to the reader code from the prior
assessment. What differs here is what you do with the result: it becomes
an *input to a provisioning request*, not something the app itself signs
into an SE credential.

```swift
struct RoomKeyProvisioningRequest: Codable {
    let physicalCardUID: String       // hex UID, for audit/migration linking only
    let reservationId: String
    let propertyId: String
    let guestAccountId: String
}

func scanThenRequestDigitalKey(uid: Data, reservationId: String) async throws {
    let request = RoomKeyProvisioningRequest(
        physicalCardUID: uid.map { String(format: "%02X", $0) }.joined(),
        reservationId: reservationId,
        propertyId: currentPropertyId,
        guestAccountId: currentGuestAccountId
    )

    // Your backend maps the reservation to a credential in the PMS/lock
    // vendor's system, then either:
    //  (a) returns a signed .pkpass (VAS-style, informational only), or
    //  (b) if you're integrated with the vendor's Apple partnership,
    //      kicks off the PKAddSecureElementPassViewController flow with
    //      an opaque provisioning payload from that vendor's Apple-facing service.
    let response = try await backend.requestDigitalKey(request)
    // handle response per (a) or (b)
}
```

Important framing for the product spec: **the physical card UID is
almost never the credential itself in this flow** — it's a lookup key your
backend uses to find "which reservation/lock does this guest belong to"
so it can ask the *lock vendor's own* provisioning backend (the one with
the Apple partnership) to issue a proper digital credential for that
lock. You are not converting the physical card's raw bytes into something
the SE accepts; the lock vendor's system generates a fresh, properly
diversified credential for the digital key independent of what's on the
plastic card.

---

## 3. How Door Readers Interact with the Secure Element (Express Mode)

Why double-click + tap works with the phone locked, Face-ID-off, or even
in **Power Reserve** (up to several hours after the phone shows "no
power"): the credential and the protocol logic run on the **Secure
Element + NFC controller**, a low-power subsystem that stays live
independent of the Application Processor (the "iOS" your app runs on)
booting. Express Mode passes are flagged so the SE will respond to a
reader's poll and complete the cryptographic handshake **without waking
the AP or requiring biometric confirmation**, subject to the pass issuer's
configured policy (Home Key requires user presence/Face ID for some
actions like "unlock for a delivery guest," but standard tap-to-enter can
be Express).

Sequence, conceptually:

1. Door reader (implementing the relevant protocol — Aliro for Home Key,
   CCC Digital Key for Car Key, or the lock vendor's Apple-certified
   firmware for Hotel Key) emits an NFC field and polls for a compatible
   applet.
2. The iPhone's NFC controller, in **card emulation mode** (the mode only
   Apple's system stack can drive), responds by routing the reader's APDU
   traffic to the specific SE applet Apple provisioned for that pass.
3. Applet and reader perform mutual authentication using diversified keys
   established during provisioning (never the raw physical card data,
   never anything your app process touches at tap-time).
4. On success, the lock actuates; usage may be reported back to the
   issuer's backend (PMS/access-control system) for logging, expiry
   enforcement, and remote revocation (e.g., at checkout, or via Find My
   marking a lost device's passes inactive).

**Your app has no runtime hook into step 2–4.** There is no delegate
callback, background task, or NFC session your code receives when a Home
Key/Hotel Key tap happens — by design, since the whole point is that it
works even when your app (and iOS itself) isn't running. Any "last used"
or "access granted" UI in your app is populated *after the fact*, via your
backend receiving a usage/webhook event from the lock vendor's system,
not by observing the tap directly.

---

## 4. Step-by-Step Implementation Roadmap

**Step 0 — Establish which lane you're in.** This determines the entire
timeline:
- **Lane A**: your hotel/property already uses a lock vendor
  (ASSA ABLOY, dormakaba, Salto, etc.) that has an existing Apple Wallet
  Hotel Key integration. Your job is largely integration, not provisioning.
- **Lane B**: no existing Apple partnership anywhere in your stack. Getting
  true SE-based unlock requires Apple's partner program regardless of your
  own code quality — budget for a business development track (NDA,
  technical review, certification) that typically runs many months and is
  owned by BD/partnerships, not engineering alone.

**Step 1 — Ship what doesn't depend on Apple approval, in parallel:**
1. Build and test the CoreNFC scan flow (§2 here / §2 of the companion
   doc) against your physical cards — useful regardless of the eventual
   unlock mechanism, e.g., for migrating a guest from a plastic card to
   whatever digital key mechanism you end up with.
2. Stand up the backend: reservation ↔ credential mapping, auth, audit
   logging.
3. Ship a **BLE-based mobile key** as your v1 unlock mechanism if your
   lock hardware supports it (most modern hotel lock vendors' SDKs
   — Assa Abloy Mobile Access, dormakaba, Salto JustIN Mobile — support
   BLE unlock today, independent of any Apple Wallet involvement). This
   gets you a shipped "tap phone, door opens" feature on a timeline your
   team controls.

**Step 2 — Pursue the Apple Wallet track:**
1. (Lane A) Integrate with your lock vendor's existing Apple-facing SDK
   for issuing the Wallet pass — this is typically a vendor API call plus
   a `PKAddSecureElementPassViewController` (or vendor-wrapped equivalent)
   present-and-confirm UI step in your app.
2. (Lane B) Engage Apple's partner program for the applicable credential
   type; in parallel, evaluate whether a VAS-based standard pass is useful
   for anything in your product *other than unlocking* (e.g., a
   "show your key" identity card at the front desk reader, or a loyalty
   check-in tap) since that part is achievable without partnership.

**Step 3 — Testing:**
- Standard `PKPass`/VAS: testable entirely with your own devices — install
  the signed `.pkpass` via `PKAddPassesViewController`, verify field
  rendering, verify webServiceURL push updates, verify NFC read against
  a VAS-capable test terminal if you have Apple's VAS agreement.
- Secure Element pass: Apple partner engineering provides reference test
  hardware/environments under NDA once you're in the program — this is not
  something reproducible with public tools or the Simulator, since the
  Simulator has no Secure Element and no NFC radio.

**Step 4 — Rollout & operations:**
- Phased pilot at a small set of locks/properties.
- Handle credential lifecycle: issuance on check-in/approval, expiry at
  checkout, remote revocation for lost/stolen devices (coordinate with
  Find My's "mark device as lost" disabling associated Wallet passes).
- Monitor via your backend's usage/webhook ingestion from the lock
  vendor's system — this is your only visibility into actual tap events
  (§3).

### Summary Decision Table

| If you are... | Do this |
|---|---|
| An app team for a property using an already-Apple-integrated lock vendor | Integrate the vendor's existing SDK; treat Apple SE provisioning as "call vendor API," not "build from PassKit primitives" |
| A lock/PMS vendor without an Apple partnership yet | Start the Apple partner conversation now (long lead time); ship BLE mobile key as the interim/parallel unlock mechanism |
| Prototyping/evaluating feasibility before any partnership exists | Build the standard `PKPass` + CoreNFC scanning pieces (both self-serve today) to validate UX; do not attempt to wire them to a real door lock — they can't unlock one |
