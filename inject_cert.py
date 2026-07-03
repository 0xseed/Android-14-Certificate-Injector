#!/usr/bin/env python3
"""
inject_cert.py — Inject a CA certificate into Android 14's system trust store via ADB.

Usage:
    python inject_cert.py <cert.pem>              # auto-selects device if only one connected
    python inject_cert.py <cert.pem> -s <serial>  # target a specific device

Requires an openssl binary either in the same directory as this script or on PATH.
"""

import argparse
import os
import subprocess
import sys

# The cert hash is computed locally and the cert is pushed with the correct
# <hash>.0 filename — no openssl needed on the device.
INJECT_SCRIPT = """
set -e
CERT_PATH="{cert_path}"
CERT_FILENAME="{cert_filename}"

# Stage existing certs so we can read them after the mount covers the dir
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Overlay the system cert directory with a writable tmpfs
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Restore existing certs into the tmpfs
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Add our new cert
cp "$CERT_PATH" "/system/etc/security/cacerts/$CERT_FILENAME"

# Fix ownership, permissions, and SELinux labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Inject into Zygote's namespace so all newly launched apps inherit the certs
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)

for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \\
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Inject into all already-running app processes too
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \\
    xargs -n1 ps -o 'PID' -P | \\
    grep -v PID
)
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \\
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait

rm -f "$CERT_PATH"
echo "SUCCESS: Certificate injected as $CERT_FILENAME"
"""


def find_openssl():
    """Return path to openssl binary: script directory first, then PATH."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = ["openssl", "openssl.exe"]
    for name in candidates:
        local = os.path.join(script_dir, name)
        if os.path.isfile(local) and os.access(local, os.X_OK):
            return local
    # Fall back to PATH
    for name in candidates:
        result = subprocess.run(
            ["where" if sys.platform == "win32" else "which", name],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().splitlines()[0]
    sys.exit(
        "openssl not found. Place an openssl binary in the same directory as this script, "
        "or add it to your PATH."
    )


def compute_cert_hash(openssl, cert_path):
    """Compute the Android subject_hash_old for the certificate."""
    result = subprocess.run(
        [openssl, "x509", "-inform", "PEM", "-subject_hash_old", "-in", cert_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(f"openssl failed:\n{result.stderr.strip()}")
    # First line is the hash; subsequent lines are the cert text
    return result.stdout.strip().splitlines()[0].strip()


def run(cmd, check=True, input=None):
    result = subprocess.run(cmd, capture_output=True, text=True, input=input)
    if check and result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip()
        sys.exit(f"Command failed: {' '.join(cmd)}\n{err}")
    return result


def adb(args, device=None, check=True, input=None):
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += args
    return run(cmd, check=check, input=input)


def get_connected_devices():
    result = run(["adb", "devices"])
    lines = result.stdout.strip().splitlines()[1:]  # skip "List of devices" header
    return [line.split("\t")[0] for line in lines if line.endswith("\tdevice")]


def resolve_device(serial):
    devices = get_connected_devices()

    if not devices:
        sys.exit("No ADB devices connected.")

    if serial:
        if serial not in devices:
            sys.exit(
                f"Device '{serial}' not found.\nConnected devices: {', '.join(devices)}"
            )
        return serial

    if len(devices) == 1:
        print(f"Device: {devices[0]}")
        return devices[0]

    print("Multiple ADB devices connected. Specify one with -s:\n", file=sys.stderr)
    for d in devices:
        print(f"  {d}", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Inject a CA certificate into Android 14's system trust store via ADB."
    )
    parser.add_argument("cert", help="Path to the CA certificate (.pem or .crt)")
    parser.add_argument(
        "-s", "--serial", help="ADB device serial (optional if only one device is connected)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.cert):
        sys.exit(f"Certificate file not found: {args.cert}")

    openssl = find_openssl()
    print(f"Using openssl: {openssl}")

    cert_hash = compute_cert_hash(openssl, args.cert)
    cert_filename = f"{cert_hash}.0"
    print(f"Certificate hash filename: {cert_filename}")

    device = resolve_device(args.serial)

    remote_cert = f"/data/local/tmp/{cert_filename}"

    print("Pushing certificate to device...")
    adb(["push", args.cert, remote_cert], device)

    # Embed the paths in the script and pipe to `su 0 sh` on stdin.
    # Avoids Magisk su's quirky handling of the -c flag and requires
    # no openssl on the device.
    script = INJECT_SCRIPT.format(cert_path=remote_cert, cert_filename=cert_filename)

    print("Running injection (approve root prompt on device if asked)...")
    result = adb(
        ["shell", "su", "0", "sh"],
        device,
        check=False,
        input=script,
    )

    output = (result.stdout + result.stderr).strip()
    if output:
        print(output)

    if "SUCCESS" not in result.stdout:
        sys.exit("\nInjection did not complete successfully.")

    print(
        "\nDone. Force-stop and relaunch any already-running apps to pick up the new certificate."
    )


if __name__ == "__main__":
    main()
