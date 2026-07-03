# inject_cert.py

Injects a CA certificate into the **system** trust store of a rooted Android 14
device over ADB, so that apps which only trust system CAs (the default since
Android 7 / API 24) will also trust the injected certificate.

This is primarily useful for security research and app debugging — e.g.
intercepting and inspecting an app's TLS traffic with a proxy tool such as
Burp Suite or mitmproxy.

## Why Android 14 needs this

- **Apps ignore user-added CAs by default.** Since Android 7 (API 24), apps
  that don't explicitly opt in via a network security config trust only the
  certificates in the **system** store, not certificates a user adds through
  Settings. Most modern apps don't opt in, so a normal "install as user CA"
  workflow is invisible to them.
- **The system store is read-only, even as root.** In Android 14, system
  certificates moved out of `/system/etc/security/cacerts` (an ext4/erofs
  path) and into the `com.android.conscrypt` **APEX module**
  (`/apex/com.android.conscrypt/cacerts`). APEX modules are mounted from
  immutable, signed images, so even a root shell can't simply `cp` a new file
  into that directory — there's no writable path to it anymore.
- **The workaround: shadow the directory, then bind-mount it back in.** The
  script:
  1. Copies the existing system certs out to a temp location.
  2. Mounts a writable `tmpfs` over `/system/etc/security/cacerts`.
  3. Restores the original certs into that tmpfs and adds the new one, fixing
     ownership, permissions, and SELinux context to match what the system
     expects.
  4. Uses `nsenter` to enter the mount namespace of `zygote`/`zygote64` and
     every already-running app process, and bind-mounts the patched
     directory over the APEX cert path (`/apex/com.android.conscrypt/cacerts`)
     inside each namespace.
- **Why per-process namespace injection?** The bind mount only affects the
  mount namespace it's performed in. Doing it in Zygote's namespace ensures
  every *newly launched* app inherits the patched trust store; doing it again
  in each running app's namespace patches processes that are already alive.
  Nothing here modifies the APEX image itself — it's a purely
  in-memory/session change that reverts on reboot.

## Requirements

- A rooted Android 14 device (tested against the APEX-based conscrypt trust
  store layout) with root shell (`su`) access, e.g. via Magisk.
- USB debugging enabled and the device authorized for ADB.
- `adb` available on your PATH.
- An `openssl` binary either on your PATH or placed next to this script
  (used locally to compute the certificate's `subject_hash_old` filename —
  no openssl is required on the device itself).

## Usage

```bash
# Auto-selects the device if exactly one is connected
python inject_cert.py <cert.pem>

# Target a specific device when multiple are connected
python inject_cert.py <cert.pem> -s <serial>
```

The script will:
1. Compute the Android-style hash filename for your cert (`<hash>.0`).
2. Push the cert to `/data/local/tmp/` on the device.
3. Run the injection routine as root (`su 0 sh`) — approve the root prompt
   on-device if you're using Magisk or similar.
4. Report `SUCCESS` on completion.

After injection, **force-stop and relaunch** any apps you want to intercept
so they pick up the patched trust store.

## Credit

- **Tim Perry (HTTP Toolkit)** — for the blog writeup explaining the Android
  14 system CA problem and the full command sequence this script automates:
  [httptoolkit.com/blog/android-14-install-system-ca-certificate](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/)
- **[g1a55er](https://infosec.exchange/@g1a55er/)** — for originally
  devising the recursive-mount-based injection method used to get a patched
  cert directory into every running process's namespace:
  [g1a55er.net/Android-14-Still-Allows-Modification-of-System-Certificates](https://www.g1a55er.net/Android-14-Still-Allows-Modification-of-System-Certificates)

## Notes / limitations

- This change is **not persistent** — it lives in tmpfs and per-process mount
  namespaces, so it's cleared on reboot. Re-run the script after rebooting
  the device.
- Apps using **certificate pinning** will still reject your CA regardless of
  trust store changes; pinning bypass is a separate, app-specific technique.
- Only use this against devices and apps you own or are authorized to test.
