# Import a single openssl-built legacy-PBE PFX into Key Vault, not a hand-built PEM

Status: accepted

Earlier attempts imported certificates into Key Vault by hand-assembling a PEM
(concatenating the Certificate key and full chain in a specific order). This was
fragile — Key Vault's PEM parser is order- and format-sensitive — and produced
inconsistent failures across renewals. We switched to building a single PKCS#12 (PFX)
file with `openssl pkcs12 -export`, which Key Vault's certificate import expects.

That alone wasn't enough: OpenSSL 3.x's default PKCS#12 encryption (PBES2/AES-256) is
not readable by Key Vault's parser (which is built on Windows CryptoAPI's older
PKCS#12 support). We must pass `-legacy` to force the older RC2-40-CBC/3DES PBE
combination Key Vault actually understands. We also always pass an explicit
`--policy` on every `az keyvault certificate import`, forcing
`content_type=application/x-pkcs12` — without it, Key Vault silently reuses whatever
content_type an *earlier* import under that same certificate name recorded (even a
broken PEM-based one from before this change), so later PFX imports fail with a
generic "unexpected format" error that has nothing to do with the PFX itself.

Consequences: this container's openssl must have the legacy provider available; a
real (non-empty) PFX password is mandatory (Key Vault treats an empty password the
same as a malformed file); the password is a fresh random value each run unless
`KEYVAULT_CERT_PFX_PASSWORD` is set, since Key Vault can't change a certificate's PFX
encryption password after import and a fixed password may be needed to export it back
out later. We verify the PFX can be read back by our own openssl before ever calling
`az`, to fail fast on our own mistakes rather than inside Azure's API.
