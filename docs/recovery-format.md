# Esec recovery identity formats

A backup consists of a generated 24-word English BIP39 phrase, a format name,
the public age recipient (for verification), and the optional passphrase. The
words carry 256 bits of OS-generated randomness plus the BIP39 checksum. The
passphrase may be empty. Do not reuse wallet seeds or invent your own words.

`esec-v1` is defined by these fixed steps:

1. Lowercase and join whitespace-separated English words with ASCII spaces.
   Require exactly 24 words and a valid BIP39 checksum.
2. Normalize the passphrase using Unicode NFKD. Do not trim it or change case.
3. Derive the 64-byte [BIP39 seed](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki):
   PBKDF2-HMAC-SHA512, 2048 iterations, mnemonic as password, `mnemonic` followed
   by the normalized passphrase as salt.
4. Argon2id with that seed as password, ASCII `esec-recovery-derivation-v1` as
   salt, 3 passes, 65536 KiB memory, 2 lanes, 32 output bytes.
5. HKDF-SHA256 with the Argon2id output as input key material, ASCII
   `esec-key-derivation-v1` as salt, ASCII `esec-recovery-age-v1` as info,
   32 output bytes.
6. Encode those 32 bytes as a native age X25519 identity. X25519 scalar handling
   and public recipient encoding follow the age implementation. The age file
   format remains standard; only the mnemonic-to-identity derivation is Esec's.

The fixed salts provide domain separation, not randomness. The phrase itself
is high-entropy secret input. These parameters must not be changed under the
same format name. Sensitive working byte buffers are cleared where practical;
Go strings and garbage collection do not provide guaranteed memory erasure.
No recovery operation transmits the phrase or derived identity to a service.

`vault-v2` reproduces the historical Esec Vault v2 root X25519 identity:
use the same English phrase handling and BIP39 seed, but preserve the exact
passphrase bytes without Unicode normalization; Argon2id salt is
`esec-identity-derivation-v1`; HKDF info is `esec-master-v2`. Other parameters
remain the same. Compatibility tests use independently generated public
vectors from the retired Vault implementation. Old pre-v2 derivations are not
supported by this option. The root identity is distinct from the random user
identity that old Vault stored wrapped in `identity.esec`.

A nonempty passphrase is required every time that identity is recovered.
Omitting it or changing it yields another valid identity, not an unprotected
copy of the original. File verification and export's expected recipient detect
mismatches. A checksum alone does not prove a phrase/passphrase pair has access.

Recovery identities and YubiKeys are independent recipients, not a quorum.
Granting a phrase-derived recipient to production deliberately provides a
software emergency path without hardware touch. Keep the private recovery
identity offline; normal CLI recovery holds it in memory for one operation.

## Public compatibility vectors

These use **all-zero 256-bit BIP39 test entropy**, never suitable for real keys.
For `esec-v1`, the public recipient with an empty passphrase is
`age1fe75xaqxj2rk5y05umcu9rpm8h0gd70ad33zjrg9ks5m0p9wpcesraulc6`;
with the test passphrase `TREZOR`, it is
`age19znpg63jwzxd803c7t9uejuwe8r03z2v9gv8ayucuddszfnp7qcqkekkvn`.
The unit tests pin these outputs and the historical Vault v2 outputs to prevent
an accidental parameter change from breaking backed-up phrases.
