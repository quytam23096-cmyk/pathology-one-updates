# Public signed-manifest monitor

This repository contains approved public release artifacts, the public certificate, and these minimal public release-operations files only. No product source, private keys, internal configuration, patient data, or custom secrets are required by this monitor.

The `Signed update manifest expiry` Actions workflow runs daily at 02:23 UTC (09:23 Asia/Bangkok), or on manual **Run workflow**. It downloads only the public manifest and its signed release index, verifies the pinned RSA-3072/SHA-256 manifest and index signatures and the 11 signed child manifests, and reports the earliest signed expiry. It does not download payload chunks, execute an installer, change a release, sign anything, change application data, or disable offline use.

- Healthy: successful run and JSON summary.
- 14 days remaining: fail the check and open one deduplicated issue mentioning the owner.
- 7 days remaining: update the same issue and post one escalation comment.
- Expired, malformed, untrusted, tampered, unavailable, or downgraded metadata: fail closed and use the same issue. This is a **monitoring failure**, not a command to install anything.
- A later healthy run closes only the issue carrying this monitor's exact marker.

Only `contents: read` and `issues: write` are granted to the built-in ephemeral `GITHUB_TOKEN`; release/content writes and signing are not permitted. `actions/checkout` is pinned to its verified v4.2.2 commit, and persisted credentials are disabled. No personal token is needed. Downloads never receive the Actions token.

For a one-time notification-path check, manually run the workflow with **notification_test = true**. The script first verifies the actual public metadata is healthy, then creates one clearly marked **[TEST]** issue using the real Actions token. No expiry, clock, version, sequence, or payload is fabricated; the workflow succeeds. A subsequent normal healthy run closes only that exact monitor-marked test issue. The test flag is rejected unless notifications are enabled and the event is an explicit manual dispatch with that boolean input true; scheduled runs cannot request a test. This proves issue API delivery, not the owner's email or push notification preferences.

## Owner action on a warning

Use the controlled local release-publisher renewal procedure and the existing authorized protected signing key. Increase sequence; never lower it. Keep accepted payload bytes and the frozen installer unchanged. Publish all signed metadata consistently, then verify using the actual client. Once accepted publicly, advance `MINIMUM_SEQUENCE` in this monitor to the new accepted sequence. Do not automatically sign in Actions and do not upload a private key.

The public key pin is the existing Nguyen Quy Tam / Pathology One publisher SPKI SHA-256 `0a63ae07c43b3e7c15c2fcdd2afd120b1d49feb9dc7e6febcc6d7f0c4c3db736`. An intentional future key bridge requires an independently reviewed monitor pin change as well as the actual client's authorized trust migration; downloading a replacement certificate is not automatic trust.

The accepted metadata floor is sequence **1010**, product version **1.0.0.9**, published as `v1.0.0.9-manifest-1010`. This is a real-key signed metadata renewal, not another application build. Keep earlier release assets for history; never reduce the sequence floor. The desktop installer is not published by this monitor.

## Operational limits / notifications

This is best-effort free monitoring, not guaranteed delivery. GitHub may delay scheduled runs, and public repository schedules can be disabled after 60 days without repository activity. The workflow must exist on the default branch and GitHub Actions and Issues must stay enabled. The repository owner must enable Actions failure and issue mention notifications, monitor their notification inbox, and check the Actions page periodically. A disabled workflow cannot alert about its own silence. Manual Run workflow remains available while Actions is enabled. These limitations do not change the offline application's operation.

This monitor implements the publisher's current v1 canonical metadata format. Unknown future fields, key rotations, a new format, or a different CDN fail visibly until the public-only monitor is reviewed. It does not replace the actual client's persistent anti-rollback state, complete package verification, or installed Standard User acceptance.

## Narrow local tests

Requires Python 3 and OpenSSL. Set `P1_MONITOR_FIXTURE_DIRECTORY` to the directory containing the accepted public `manifest.json` and `release-index.json`; optionally set `P1_MONITOR_OPENSSL` to the OpenSSL executable. Run `python3 operations/test_manifest_monitor.py`. Tests use the accepted signed metadata and mocked notification calls only; no private key, package installation, external write, or product regression run occurs.

References: [GitHub schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), [least-privilege built-in token](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token), [pinning actions](https://docs.github.com/en/actions/reference/security/secure-use).
