Architecture Decision Report 008 - The following ADR refers to the chosen library for reading passwords from the command line without echoing them to the terminal. We decided on rpassword.

Context:
Commands in project require the user to enter a master password interactively. 
Per requirement F-19 of the specification, secrets must never be passed as command-line arguments or logged, and password input must be done in an interactive mode without echo. 
We needed a library that disables terminal echo while the user types the password, so that the password is not visible on screen and not stored in shell history.

Basis:
  - Widely used and well-maintained Rust crate for password input
  - Cross-platform (Linux, macOS, Windows) without platform-specific code on our side
  - Easy to use
  - Reads from the controlling terminal, so the password is not captured if stdin is redirected
  - Returns a String which we immediately wrap in Zeroizing (consistent with F-15, F-16, F-19)
