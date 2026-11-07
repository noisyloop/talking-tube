# talking-tube
Talking tube is a replacement for Discord in Rust, with more encryption.

* Communities and channels like Discord, but no email, phone or login. Your
  identity is a key made on your device.
* DMs use the Signal protocol (X3DH + Double Ratchet), ported from
  [Shadow](https://github.com/noisyloop/Shadow).
* Channels use sender keys first, then MLS.
* Anyone can run a relay. Relays only ever see ciphertext.
* Plugins and bots run on the client, after decryption.

Status: scaffold only. Nothing is implemented yet.

* [Architecture](docs/ARCHITECTURE.md)
* [Encryption, and whether we can use Signal's](docs/ENCRYPTION.md)
