# Description

Ferris-Vault-Server is the server part of the [Ferris-Vault-TUI](https://github.com/Philb37/ferris-vault-tui) password manager written in rust.

# Project Architecture

todo

The storage part will be in on disk for the first version. Might be a good idea to migrate to postgres.

# Security

This project is design to be a Zero-knowledge architecture server based on the OPAQUE protocol.

In a production scenario the password vault in itself should not be stored where the TUI is.

The password-file will contain all the information needed for the OPAQUE protocol (user private-public keypair, server public key, and user encryption key), it will be crypted using the user's master-password, and the vault will be crypted using the encryption-key stored inside the password-file.

You can find information about Zero-knowledge Architecture and OPAQUE here :

- [NordPass Zero-Knowledge Architecture](https://nordpass.com/features/zero-knowledge-architecture/)
- [Cloudflare blogpost on OPAQUE](https://blog.cloudflare.com/opaque-oblivious-passwords/)
- [OPAQUE resource](https://opaque-auth.com/docs/resources)
- [Audited Rust OPAQUE Implementation](https://github.com/facebook/opaque-ke/tree/main)
- [OPAQUE RFC](https://datatracker.ietf.org/doc/rfc9807/)
- [OPAQUE Paper](https://eprint.iacr.org/2018/163.pdf)