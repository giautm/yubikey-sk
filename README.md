# yubikey-sk

A FIDO2 Security Key provider library for Apple's OpenSSH. This bridges OpenSSH's `SSH_SK_PROVIDER` interface to YubiKey hardware tokens via `libfido2`.

## Requirements

- macOS with OpenSSH 8.2+ (ships with macOS)
- [libfido2](https://github.com/Yubico/libfido2) — `brew install libfido2`
- A YubiKey with FIDO2 support (YubiKey 5 series, Security Key series)

## Build

```sh
make
```

For debug output:
```sh
make debug
```

## Install

```sh
make install          # installs to /usr/local/lib
# or
make install PREFIX=$HOME/.local
```

## Usage

Set the `SSH_SK_PROVIDER` environment variable to point to the library:

```sh
export SSH_SK_PROVIDER=/path/to/libyubikey-sk.dylib
```

Or add to your `~/.ssh/config`:

```
SecurityKeyProvider /path/to/libyubikey-sk.dylib
```

### Generate a FIDO2 SSH key (stored on YubiKey)

```sh
# ECDSA-SK
ssh-keygen -t ecdsa-sk

# ED25519-SK
ssh-keygen -t ed25519-sk

# Resident key (discoverable, stored on YubiKey)
ssh-keygen -t ed25519-sk -O resident
```

### Load resident keys from YubiKey

```sh
ssh-add -K
ssh-keygen -K   # download to ~/.ssh/
```

### Authenticate

```sh
ssh user@host   # will blink YubiKey for touch confirmation
```

### Debug

Enable debug logging:
```sh
export YUBIKEY_SK_DEBUG=1
ssh user@host
```

## How it works

OpenSSH loads this shared library at runtime and calls:

- `sk_api_version()` — returns API version compatibility
- `sk_enroll()` — generates a new FIDO2 credential on the YubiKey
- `sk_sign()` — performs a FIDO2 assertion (signs a challenge)
- `sk_load_resident_keys()` — enumerates discoverable credentials

The library uses `libfido2` to communicate with the YubiKey over USB HID.

## License

ISC
