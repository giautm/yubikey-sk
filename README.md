# yubikey-sk

A FIDO2 Security Key provider library for Apple's OpenSSH on macOS.

Apple's macOS ships with OpenSSH but does not include a built-in SK (Security Key) middleware for hardware tokens. This library bridges OpenSSH's `SSH_SK_PROVIDER` interface to YubiKey hardware tokens via [libfido2](https://github.com/Yubico/libfido2), enabling `ed25519-sk` and `ecdsa-sk` key types.

## Why?

macOS's bundled OpenSSH supports FIDO2/U2F key types (`-sk` suffix) but:
- Does **not** ship with a usable SK provider library
- The built-in `ssh-agent` does **not** support SK provider loading
- Apple's OpenSSH passes raw signing data (not pre-hashed), unlike upstream OpenSSH

This library handles all of the above, letting you use your YubiKey for SSH authentication on macOS with zero hassle.

## Requirements

- macOS 13+ with OpenSSH 9.0+ (ships with macOS)
- [libfido2](https://github.com/Yubico/libfido2) — `brew install libfido2`
- A YubiKey with FIDO2 support (YubiKey 5 series, Security Key series)

## Build

```sh
brew install libfido2
make
```

For a debug build (always prints diagnostics to stderr):
```sh
make debug
```

## Install

```sh
make install                    # installs to /usr/local/lib
make install PREFIX=$HOME/.local  # or a custom prefix
```

## Usage

### Configuration

Add to your shell profile (`~/.zshrc`):

```sh
export SSH_SK_PROVIDER=/usr/local/lib/libyubikey-sk.dylib
```

Or per-host in `~/.ssh/config`:

```
Host github.com
    SecurityKeyProvider /usr/local/lib/libyubikey-sk.dylib
    IdentityFile ~/.ssh/id_ed25519_sk
```

### Adding SK keys to ssh-agent

Apple's built-in ssh-agent supports loading SK keys via a provider library:

```sh
ssh-add -S /usr/local/lib/libyubikey-sk.dylib ~/.ssh/id_ed25519_sk
```

This registers the key with the agent so subsequent SSH connections use it automatically.

### Generate a FIDO2 SSH key

```sh
# ED25519-SK (recommended)
ssh-keygen -t ed25519-sk

# ECDSA-SK
ssh-keygen -t ecdsa-sk

# Resident key (discoverable credential stored on YubiKey)
ssh-keygen -t ed25519-sk -O resident
```

### Load resident keys from YubiKey

```sh
ssh-keygen -K   # downloads discoverable keys to ~/.ssh/
```

### Authenticate

```sh
ssh user@host   # YubiKey will blink — tap to confirm
```

### Troubleshooting

Enable debug logging:
```sh
export YUBIKEY_SK_DEBUG=1
ssh -v user@host
```

## How it works

OpenSSH loads this shared library (`.dylib`) at runtime via `dlopen` and calls the SK middleware API:

| Function | Purpose |
|----------|---------|
| `sk_api_version()` | Returns API version (0x000a0000) |
| `sk_enroll()` | Generates a new FIDO2 credential on the YubiKey |
| `sk_sign()` | Performs a FIDO2 assertion (signs a challenge) |
| `sk_load_resident_keys()` | Enumerates discoverable credentials |

The library uses `libfido2` to communicate with the YubiKey over USB HID (via macOS IOKit).

### Apple OpenSSH compatibility

Apple's OpenSSH diverges from upstream in how it calls `sk_sign()` — it passes the full signing data (not a pre-computed SHA-256 hash). This library detects the data length and handles both cases transparently.

## Supported hardware

- YubiKey 5 series (USB-A, USB-C, NFC)
- YubiKey 5 FIPS series
- Security Key by Yubico (USB-A, NFC)
- Any FIDO2-compliant key accessible via libfido2

## Contributing

1. Fork the repo
2. Create a feature branch
3. Make your changes (run `make debug` to test)
4. Submit a pull request

## License

ISC
