# Verifying esec Releases

All esec releases are signed and include provenance attestations to ensure authenticity and integrity. This document explains how to verify downloaded artifacts.

## Release Artifacts

Each release includes:

| File | Description |
|------|-------------|
| `esec_X.Y.Z_{os}_{arch}.tar.gz` | Platform binary archives |
| `esec_X.Y.Z_{arch}.deb` | Debian packages |
| `esec_X.Y.Z_source.tar.gz` | Source archive |
| `checksums.txt` | SHA256 checksums for all artifacts |
| `checksums.txt.sigstore.json` | Cosign signature bundle |
| `*.sbom.json` | SBOM (Software Bill of Materials) for each archive |

## Quick Verification

The easiest way to verify a release artifact is using the GitHub CLI:

```bash
gh attestation verify esec_*.tar.gz --owner mscno
```

This verifies the artifact was built by the official GitHub Actions workflow.

## Checksum Verification

### Download and Verify Checksums

```bash
# Download the checksums file
curl -LO https://github.com/mscno/esec/releases/latest/download/checksums.txt

# Verify a downloaded artifact
sha256sum -c checksums.txt --ignore-missing

# Or on macOS
shasum -a 256 -c checksums.txt --ignore-missing
```

### Verify Checksum Signature with Cosign

The checksums file is signed using [Cosign](https://github.com/sigstore/cosign) with keyless (OIDC) signing.

```bash
# Install cosign if needed
# brew install cosign  # macOS
# go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # Go

# Download the signature bundle
curl -LO https://github.com/mscno/esec/releases/latest/download/checksums.txt.sigstore.json

# Verify the signature
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "https://github.com/mscno/esec" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

A successful verification confirms:
1. The checksums file was signed by the esec GitHub Actions workflow
2. The signature is valid and hasn't been tampered with

## GitHub Attestation Verification

GitHub attestations provide SLSA provenance, proving artifacts were built in GitHub Actions.

### Prerequisites

- GitHub CLI (`gh`) version 2.49.0 or later

### Verify Any Artifact

```bash
# Verify a binary archive
gh attestation verify esec_1.0.0_linux_amd64.tar.gz --owner mscno

# Verify a Debian package
gh attestation verify esec_1.0.0_amd64.deb --owner mscno

# Verify the source archive
gh attestation verify esec_1.0.0_source.tar.gz --owner mscno

# Verify checksums
gh attestation verify checksums.txt --owner mscno

# Verify an SBOM
gh attestation verify esec_1.0.0_linux_amd64.tar.gz.sbom.json --owner mscno
```

### Understanding the Output

A successful verification shows:
- The workflow that produced the artifact
- The repository and commit
- The SLSA build level

## SBOM (Software Bill of Materials)

Each release includes SBOM files in SPDX JSON format, listing all dependencies.

### View SBOM Contents

```bash
# Download an SBOM
curl -LO https://github.com/mscno/esec/releases/latest/download/esec_1.0.0_linux_amd64.tar.gz.sbom.json

# Pretty print the SBOM
jq . esec_1.0.0_linux_amd64.tar.gz.sbom.json

# List all packages in the SBOM
jq '.packages[].name' esec_1.0.0_linux_amd64.tar.gz.sbom.json
```

### Scan SBOM for Vulnerabilities

You can use tools like [Grype](https://github.com/anchore/grype) to scan the SBOM for known vulnerabilities:

```bash
# Install grype
# brew install grype  # macOS
# curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan the SBOM
grype sbom:esec_1.0.0_linux_amd64.tar.gz.sbom.json
```

## Complete Verification Example

Here's a complete example verifying a Linux release:

```bash
# Set the version
VERSION=1.0.0

# Download all verification files
curl -LO "https://github.com/mscno/esec/releases/download/v${VERSION}/esec_${VERSION}_linux_amd64.tar.gz"
curl -LO "https://github.com/mscno/esec/releases/download/v${VERSION}/checksums.txt"
curl -LO "https://github.com/mscno/esec/releases/download/v${VERSION}/checksums.txt.sigstore.json"

# 1. Verify checksum
sha256sum -c checksums.txt --ignore-missing

# 2. Verify checksum signature
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "https://github.com/mscno/esec" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# 3. Verify GitHub attestation
gh attestation verify "esec_${VERSION}_linux_amd64.tar.gz" --owner mscno

# 4. Extract and use
tar xzf "esec_${VERSION}_linux_amd64.tar.gz"
./esec --version
```

## Troubleshooting

### "no attestations found"

This error means the artifact doesn't have a GitHub attestation. This could happen if:
- You're verifying an older release (before attestations were added)
- The artifact was modified after download
- The download was corrupted

### Checksum Mismatch

If `sha256sum -c` fails:
- Re-download the artifact
- Ensure you're comparing against the correct version's checksums
- Check for download corruption or tampering

### Cosign Verification Fails

If cosign verification fails:
- Ensure you have the latest version of cosign
- Check that the signature bundle matches the checksums file version
- Verify you're using the correct certificate identity and issuer

## Security Considerations

- Always verify artifacts before running them, especially in production
- Keep your verification tools (`gh`, `cosign`, `sha256sum`) up to date
- Report any verification failures to the maintainers
