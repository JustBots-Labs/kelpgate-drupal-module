# Changelog

## Unreleased

The first public version. It has not been tagged as a release yet.

- Sends each uploaded file to the Kelpgate scanning service during Drupal file validation, and rejects infected files with a validation error.
- A failure policy decides what happens when the scanner cannot give a verdict: `block` (the default) or `allow`.
- Detections are written to the `kelpgate` log channel with the file's SHA-256.
- The client secret is read from `settings.php` or Drupal state and is never stored in exported configuration.
- Supports Drupal 9.5, 10 and 11 on PHP 7.4 to 8.4.
- Install with `git clone` into `modules/contrib/kelpgate`, or with Composer from the GitHub repository until the module is on Packagist.
