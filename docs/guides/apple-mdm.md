# Apple MDM
<!-- group: Manage endpoints; order: 17; pages: /mdm -->

Make mustra the MDM server for your Macs: enroll them with a link, see what they report, install and remove configuration profiles, restart them, and, with a second person's approval, lock or erase one.

This is mustra's own MDM. Fleet and Intune keep working as before (**Administration → macOS MDM**, **Integrations**); a Mac enrolls in one MDM at a time, so choose one per Mac.

## Before you start

- Setting it up needs **Manage settings** (`settings.manage`) and **Manage integrations** (`integrations.manage`).
- Enrollment links, the profile library and commands need **Deploy software and run actions** (`deploy.manage`). Reading a lock or erase PIN needs **Read BitLocker recovery keys**, the same permission (`enforce.recovery_keys`). Approving a lock or erase needs **Decide approvals** (`approvals.decide`).
- The server needs the credential vault (`MUSTRA_CREDENTIAL_ENCRYPTION_KEY`): every private key here is stored sealed by it.
- The console's public URL must be **https** with a certificate the Macs trust (a public CA, or one your Macs already trust). Macs talk to `<public URL>/mdm/checkin` and `/mdm/connect`. A reverse proxy or tunnel in front of mustra is fine: Macs sign every message (the `Mdm-Signature` header), so the proxy may end TLS.
- An Apple ID that belongs to the organization, not a person, for the push certificate.

## 1. Get a push certificate

Apple only wakes a Mac for a server holding an **MDM push certificate**, and only issues one for a request signed by an **MDM vendor**. mustra is not an Apple MDM vendor and cannot sign one. You have three honest options:

- **Your own vendor certificate.** An Apple Developer Enterprise Program membership can request the *MDM CSR* certificate; use it to sign the request yourself.
- **A vendor signing service.** Some MDM vendors and community services sign requests for others. Check its terms, and that you are allowed to use it for your organization.
- **Ask your MDM or reseller** if you already have a relationship with one.

Then:

1. Open **Apple MDM → Setup** and choose **Make a certificate request**. mustra keeps the private key in its vault and shows the request.
2. Have the request signed by the vendor; you get back a signed request (often a `.plist` or `.b64` file).
3. Sign in at **identity.apple.com** (Apple Push Certificates Portal) with the organization's Apple ID, choose **Create a Certificate**, upload the signed request and download the `.pem`.
4. Back in **Setup**, paste the certificate into **Certificate (PEM) from Apple** and choose **Upload push certificate**. Leave the key empty: the one made with the request is used.

If you already have a push certificate and key (for example a `.p12` from Keychain Access), upload those instead.

**Renew it every year with the same Apple ID**, using **Renew** at identity.apple.com rather than **Create**: a renewed certificate keeps its topic. A new certificate has a new topic, and every Mac would have to enroll again; mustra refuses that swap while Macs are enrolled unless you ask for it. The certificate's expiry is shown in Setup, warned about from 30 days out, and announced like other expiring certificates (**Certificates → Alerts**).

## 2. Create the MDM CA and turn it on

1. Choose **Create the MDM CA**. It issues each Mac its own identity certificate and lives in the vault. It is created once; replacing it would cut off every enrolled Mac.
2. Optionally sign the enrollment profile under **Profile signing**: paste a certificate the Macs already trust (the console's TLS certificate is a good choice) with its chain and key. Without one, the profile installs but shows as unverified.
3. Set the organization name Macs show, and choose **Turn on**. It turns on only when nothing is missing.

Turned off, the device endpoints answer as if they did not exist; enrolled Macs stay enrolled and pick up where they left off when it is on again.

## 3. Enroll a Mac

1. Under **Enrollment**, create a link: a label, how many Macs it may enroll and how long it works (a week by default, at most 30 days). The link is shown once.
2. On the Mac, open the link in Safari. It downloads the enrollment profile.
3. Open **System Settings → Privacy & Security → Profiles** (on older macOS, **System Settings → Profiles**), choose the downloaded profile and **Install**. This is user-approved enrollment: the person at the Mac agrees to it.

Each download counts as one use. A link that is used up, expired or revoked hands out nothing, so a Mac nobody sent a link to cannot enroll.

When the Mac finishes enrolling, mustra asks it for its device information, security state and installed profiles. A Mac that also runs the mustra agent is linked to that endpoint by serial number, and the endpoint's page shows it under **Apple MDM**.

## Send commands

Open **Apple MDM → Macs**, pick a Mac, choose a command and **Send**. mustra queues it and asks Apple to wake the Mac; the Mac fetches it when it can. Each command's state is shown as it changes:

- **Waiting for the Mac**: queued, not yet fetched. You can cancel it.
- **With the Mac**: delivered, no answer yet. If the Mac never answers it is offered again on its next check-in, at most three times, then marked failed.
- **Mac said not now**: the Mac deferred it (for example while it is locked); it is offered again on its next check-in.
- **Done**, **Failed** (with the Mac's error), **Refused as malformed**, **Cancelled**, or **Expired unanswered** after 30 days.

The commands:

- **Device information**, **Security information**, **Installed applications**, **Installed profiles**: what the Mac reports is shown on its page.
- **Install a profile** from the profile library, and **Remove a profile** by the library entry or by its identifier.
- **Restart**, optionally letting the person signed in postpone it.
- **Lock with a PIN** and **Erase** always wait for a second person's approval under **Access → Approvals**, whatever approval policies say, and an API token cannot ask for them. Erase works on one Mac at a time and asks you to type its serial number. mustra makes a six-digit PIN when the command is queued; choose **Show PIN** in the command history to read it (recorded in the audit log).

Approval policies and action groups can also name the **mdm** module, like any other module. A Mac not linked to a mustra endpoint is in no computer group, so only an account whose management rights cover the whole fleet can act on it.

## The profile library

Under **Profile Library**, add `.mobileconfig` files, signed or unsigned. A profile with an MDM payload is refused: it would move the Mac to another server. Profiles can hold Wi-Fi passwords and certificates, so the library is visible only with `deploy.manage`.

## Not in this release

iPhone and iPad, Automated Device Enrollment (Apple Business Manager), declarative device management, apps from Apple Business Manager, bootstrap tokens and macOS updates through this MDM are not supported yet (use Fleet for macOS updates). An enrolled Mac's identity certificate lasts about 13 months; re-enroll it before then.
