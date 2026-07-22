Architecture Decision Report 004
The following ADR refers to a chosen AEAD algorithm. Our group decided on ChaCha20 - Poly1305.

*Basis*
- It provides encryption and integrity at the same time
- Fast
- Frequently used in modern systems
- The use of associated_data makes it possible to include data that should not be encrypted, but still must be protected against modification.
