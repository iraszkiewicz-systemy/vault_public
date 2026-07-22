Architecture Decision Report 003
The following ADR refers to a chosen KDF to derive wrap_key and header_mac_key. Our group decided on HKDF-SHA256.

*Basis*
- deterministic
- HMAC-SHA256 is considered extremely safe
- It allows deriving multiple independent keys from one master_key. Different "info" values produce different derived keys, even when the same master_key is used
