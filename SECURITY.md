# Security

For a suspected vulnerability, use GitHub's private vulnerability reporting for
this repository if available. Otherwise contact support@filetrust.io to arrange
a private report. Do not put private keys, operational settings or unpatched
exploit details in public issues.

Include the affected public source revision, impact and a minimal reproduction.
Remove credentials and personal or infrastructure information from attachments.

This initial source publication is intended for review and local development.
It is not a production network launch or a claim that the protocol is audited.
Security updates affecting consensus or deployed contracts require a reviewed
network upgrade or governance process.

The pinned Hardhat build/deployment dependency tree currently has published npm
security advisories. They are not evidence of leaked credentials or a finding in
the deployed Solidity code, but require review before production deployment or
processing untrusted compiler inputs, archives or RPC responses. Compiler and
OpenZeppelin versions are preserved from the reviewed protocol source rather
than silently upgraded during publication. Use isolated development tooling.
