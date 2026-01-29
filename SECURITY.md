# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest | :x:               |

We only provide security fixes for the latest release. We recommend always using the most recent version.

## Reporting a Vulnerability

We take the security of esec seriously. If you believe you have found a security vulnerability, please report it responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via [GitHub Security Advisories](https://github.com/mscno/esec/security/advisories/new).

Alternatively, you can email the maintainer directly at: oss@mscno.dev

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., key exposure, cryptographic weakness, injection)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment of the vulnerability

### Response Timeline

- **Initial Response**: Within 3 business days
- **Status Update**: Within 7 business days
- **Resolution Target**: Within 30 days for critical issues

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report
2. **Assessment**: We will investigate and assess the severity
3. **Updates**: We will keep you informed of our progress
4. **Resolution**: We will work on a fix and coordinate disclosure
5. **Credit**: We will credit you in the release notes (unless you prefer anonymity)

## Scope

The following are in scope for security reports:

- Cryptographic vulnerabilities in the encryption/decryption process
- Private key exposure or leakage
- Authentication or authorization bypasses
- Command injection in the `run` command
- Path traversal vulnerabilities
- Dependencies with known security vulnerabilities

### Out of Scope

- Vulnerabilities in dependencies that don't affect esec's functionality
- Issues that require physical access to the user's machine
- Social engineering attacks
- Denial of service attacks that require significant resources

## Security Best Practices

When using esec:

1. **Never commit** `.esec-keyring` or private keys to version control
2. **Add to `.gitignore`**: `.esec-keyring`
3. Use **environment-specific keys** for different deployments
4. Rotate keys periodically, especially after team member departures
5. Verify release artifacts using the instructions in [VERIFICATION.md](VERIFICATION.md)

## Verification

All releases are signed and include provenance attestations. See [VERIFICATION.md](VERIFICATION.md) for instructions on verifying release artifacts.
