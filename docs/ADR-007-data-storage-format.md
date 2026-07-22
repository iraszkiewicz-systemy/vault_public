Architecture Decision Report 007 - data storage format
The following ADR refers to the chosen data storage format for vault records. Our group decided on CBOR (RFC 8949).

Context
The project requires a method for storing user records such as logins and passwords within an encrypted file. The format must be efficient, support binary data natively, and ensure a deterministic representation of data to maintain cryptographic integrity.

Basis
- Native Binary Support: CBOR handles binary data directly, unlike text-based formats. This means keys and salts do not require conversion to text, which saves storage space and simplifies the implementation.

- Canonical Encoding: CBOR provides a deterministic encoding standard. After decryption, the data always maintains an identical bit-level representation. This is critical for ensuring that checksums and message authentication codes always match.

- Extensibility: Unlike raw TLV, CBOR offers ready-to-use structures such as maps and lists. This facilitates future expansion of the vault with new data types while maintaining the strict binary rigor required by the specification.

Comparison
JSON: Rejected. As a text format, JSON would require Base64 encoding for binary secrets, increasing file size and complicating the program. It also lacks inherent canonicality, making it difficult to maintain a constant field order.

TLV: Rejected. While secure, TLV does not provide the flexible high-level structures that CBOR offers, which would make future updates to the data schema much more difficult to implement.
