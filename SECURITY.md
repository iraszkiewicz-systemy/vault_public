# Security Policy

## Supported versions

This project is developed as part of an academic team project. Security fixes are provided for the current development version and the final release tag `v1.0.0`.

## Reporting a vulnerability

If you find a security vulnerability, do not open a public GitHub issue with exploit details.

Please report it privately to the project team by contacting one of the maintainers.

Include:
- affected version or commit hash,
- description of the issue,
- steps to reproduce,
- expected and actual behavior,
- possible impact,
- suggested fix, if known.

## Scope

Security reports may include:
- incorrect cryptographic behavior,
- vault file tampering not detected by `open` or `verify --with-password`,
- malformed vault files causing crashes,
- secret leakage through CLI output, logs, arguments or files,
- unsafe handling of passwords, keys, or decrypted records,
- broken `changepass`, `upgrade-kdf`, `attach`, `extract`, or `verify`.

Out of scope:
- phishing of the master password,
- malware running on the user's machine,
- attacks requiring access to RAM during an active session,
- malicious modification of the compiled binary or dependencies,
- denial-of-service through unrealistic resource exhaustion.

## Security expectations

The project aims to provide:
- confidentiality of records without knowledge of the master password,
- detection of vault file modifications,
- resistance to KDF or AEAD downgrade attacks,
- costly offline brute-force attempts through Argon2id,
- rejection of the old password after `changepass` for the current vault file.

## Responsible disclosure

Please give the team time to reproduce and fix the issue before disclosing details publicly.
