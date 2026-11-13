# Changelog

## Unreleased

The first public version. It has not been tagged as a release yet.

- Sends each uploaded file to the Kelpgate scanning service during Drupal file validation, and rejects infected files with a validation error.
- A failure policy decides what happens when the scanner cannot give a verdict: `block` (the default) or `allow`.
- Detections are written to the `kelpgate` log channel with the file's SHA-256.
- The client secret is read from `settings.php` or Drupal state and is never stored in exported configuration.
- Setting names and environment variables match the other Kelpgate clients and the WordPress plugin ([client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md)): `max_mb` (not `max_scan_mb`), and `KELPGATE_API_URL`, `KELPGATE_TOKEN_URL`, `KELPGATE_AUTH_MODE`, `KELPGATE_CLIENT_ID`, `KELPGATE_CLIENT_SECRET`, `KELPGATE_TOKEN`, `KELPGATE_FAIL_ACTION`, `KELPGATE_MAX_MB` and `KELPGATE_TIMEOUT_SECONDS` can force each setting.
- Every scan sends an `Idempotency-Key` (one per scan), so a repeated request, such as the retry after a refreshed token, is not counted against the plan's quota twice. There is nothing to configure ([client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md#idempotency)).
- Supports Drupal 9.5, 10 and 11 on PHP 7.4 to 8.4.
- Install with `git clone` into `modules/contrib/kelpgate`, or with Composer from the GitHub repository until the module is on Packagist.
