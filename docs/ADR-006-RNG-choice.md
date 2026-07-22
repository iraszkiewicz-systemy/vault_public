Architecture Decision Report 006
The following ADR refers to a random number generator. Our group decided on OsRng.

*Basis*
- It is a Cryptographic Secure Pseudo-Random Number Generator (CSPRNG) or uses one, making it suitable for security-sensitive tasks. 
- Instead of using a formula for pseudo-random numbers, it fetches actual random numbers from the OS.
