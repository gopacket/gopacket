# Security Policy for `gopacket/gopacket` Module

## Supported Versions

This section provides information about the versions of the `gopacket` module that are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

It is highly recommended to use the supported versions to ensure the security and stability of your projects. Unsupported versions will not receive security updates, and using them may expose your projects to vulnerabilities.

## Reporting a Vulnerability

If you discover a vulnerability in the `gopacket` module, please take the following steps to report it:

1. **Contact**: please use the private fork and PR function to raise the issue.

2. **Acknowledgment**: You can expect to receive an acknowledgment of your vulnerability report within a week of submission.

3. **Updates**: The security team will keep you updated on the status of your report and the planned resolution timeline. Updates will be provided at least once a week until the issue is resolved.

4. **Disclosure**: If the vulnerability is confirmed, the security team will work to promptly release a fix. Details about the vulnerability and the fix will be publicly disclosed after the release, allowing users to update and secure their systems.

5. **Acceptance or Decline**: If your report is accepted, you will be credited for the discovery, and the details will be shared in the public disclosure. If the report is declined, the security team will provide an explanation for the decision.

## What Gets a CVE

From 20 November 2026, a bug whose only effect is crashing `gopacket`, or a program built with `gopacket` as a dependency, does not get its own CVE. A panic on a malformed packet is the usual case. These reports are still accepted as bugs and fixed.

Denial of service at the operating system level still qualifies: a bug that takes down or degrades the host itself, beyond the process using `gopacket`.

The volume of crash reports makes one CVE per bug impractical. Advisories and CVE requests made before this date stand and will not be withdrawn.

Your cooperation and responsible disclosure are greatly appreciated in helping to keep the `gopacket/gopacket` module and its users secure.

Keep in mind that `gopacket` is maintained by only a few people, so if there are multiple bugs it might take a while for them to get fixed.
