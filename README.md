# Kelpgate Malware Scanner for Drupal

Scans files uploaded to Drupal with the Kelpgate scanning API and rejects infected ones during file validation, before they are saved.

Requires Drupal 9.4, 10 or 11, PHP 7.4+, and a Kelpgate account (client ID and secret from the Kelpgate Console).

## Install

```bash
composer require kelpgate/kelpgate
drush en kelpgate
```

Or copy the module into `modules/contrib/kelpgate` and enable it. Then open `/admin/config/security/kelpgate` and enter the API URL, token URL, client ID and client secret.

## Behaviour

- Hooks `hook_file_validate()`, so it covers file fields, Media Library and CKEditor image uploads.
- A file is rejected only when the API reports it as infected (HTTP 406). The detection is written to the `kelpgate` watchdog channel with the file's SHA-256.
- If the scanner cannot be reached, `fail_action` decides: `block` rejects the upload, `allow` accepts it. Files above `max_scan_mb` follow the same policy.
- Files are streamed to the API rather than loaded into memory. Access tokens are cached and renewed shortly before expiry. The API and token URLs must use HTTPS.
- The settings form requires the `administer kelpgate` permission.

## Configuration

Settings live in `kelpgate.settings`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Turn scanning on or off |
| `api_url` | | Base URL of the scanning API |
| `token_url` | | OAuth2 token endpoint |
| `auth_mode` | `oauth2` | `oauth2` or `token` |
| `client_id` | | OAuth2 client ID |
| `fail_action` | `block` | `block` or `allow` when the scanner is unavailable |
| `max_scan_mb` | `50` | Largest file scanned |
| `timeout_seconds` | `45` | HTTP timeout |

The client secret is not stored in exported configuration. Set it in `settings.php` (preferred) or through the settings form, which keeps it in Drupal state:

```php
$settings['kelpgate_client_secret'] = getenv('KELPGATE_CLIENT_SECRET');
// auth_mode "token" uses: $settings['kelpgate_api_token']
```

Other values can be pinned the usual way:

```php
$config['kelpgate.settings']['api_url']   = 'https://api.example.com';
$config['kelpgate.settings']['token_url'] = 'https://auth.example.com/oauth2/token';
$config['kelpgate.settings']['client_id'] = getenv('KELPGATE_CLIENT_ID');
```

## Try it

Upload a file containing the standard EICAR test string through any file or media field:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

The upload is rejected and a message appears under **Reports > Recent log messages**.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
