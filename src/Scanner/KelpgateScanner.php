<?php

namespace Drupal\kelpgate\Scanner;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;
use Drupal\file\FileInterface;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;

/**
 * Service to perform malware scans against Kelpgate REST API via OAuth2.
 */
class KelpgateScanner {

  /**
   * Fetch a new OAuth2 token when fewer than this many seconds of validity remain.
   */
  const REFRESH_AHEAD_SECONDS = 120;

  /**
   * The HTTP client.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The logger channel.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * Cache backend for OAuth2 tokens.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * The state service (database-only storage, never part of a config export).
   *
   * @var \Drupal\Core\State\StateInterface|null
   */
  protected $state;

  /**
   * Constructs a KelpgateScanner service.
   */
  public function __construct(ClientInterface $http_client, ConfigFactoryInterface $config_factory, LoggerInterface $logger, CacheBackendInterface $cache, ?StateInterface $state = NULL) {
    $this->state = $state;
    $this->httpClient = $http_client;
    $this->config = $config_factory->get('kelpgate.settings');
    $this->logger = $logger;
    $this->cache = $cache;
  }

  /**
   * Checks if scanning is enabled.
   */
  public function isEnabled(): bool {
    return (bool) $this->config->get('enabled');
  }

  /**
   * Resolves a credential without relying on exportable config.
   *
   * Order: settings.php ($settings['kelpgate_client_secret'] / ['kelpgate_api_token']), then the
   * State API (where the settings form stores it), then legacy config values from older installs.
   * Config is exported by `drush config:export` and usually committed, so it is the last resort.
   */
  protected function secret(string $name): string {
    $fromSettings = Settings::get('kelpgate_' . $name);
    if (!empty($fromSettings)) {
      return trim((string) $fromSettings);
    }
    if ($this->state) {
      $fromState = $this->state->get('kelpgate.' . $name);
      if (!empty($fromState)) {
        return trim((string) $fromState);
      }
    }
    return trim((string) $this->config->get($name));
  }

  /**
   * Obtains an active Bearer token via OAuth2 or static config.
   */
  public function getAccessToken(): ?string {
    $authMode = $this->config->get('auth_mode') ?: 'oauth2';
    if ($authMode === 'token') {
      return $this->secret('api_token') ?: null;
    }

    $clientId = trim((string) $this->config->get('client_id'));
    $clientSecret = $this->secret('client_secret');
    if (empty($clientId) || empty($clientSecret)) {
      $this->logger->error('Kelpgate OAuth2 credentials missing.');
      return null;
    }

    $cid  = 'kelpgate_oauth_token_' . md5($clientId);
    $lock = 'kelpgate_oauth_lock_' . md5($clientId);

    // The cache holds the token plus its real expiry time. Older versions cached the bare token
    // string (treated as "valid, expiry unknown": used as before and replaced when it expires).
    $token = '';
    $expires = 0;
    if ($cached = $this->cache->get($cid)) {
      $data = $cached->data;
      if (is_array($data) && !empty($data['t'])) {
        $token = (string) $data['t'];
        $expires = (int) ($data['e'] ?? 0);
      }
      elseif (is_string($data) && $data !== '') {
        $token = $data;
      }
    }

    if ($token !== '') {
      $remaining = $expires > 0 ? $expires - time() : PHP_INT_MAX;
      if ($remaining > self::REFRESH_AHEAD_SECONDS) {
        return $token;
      }
      // Refresh ahead: the token is about to expire, so fetch a new one now instead of letting an
      // upload hit a 401 at the boundary. One request refreshes; concurrent uploads keep using the
      // still-valid token meanwhile.
      if ($remaining > 0 && $this->cache->get($lock)) {
        return $token;
      }
    }
    // A token that has not actually expired is still usable if a refresh is impossible or fails.
    $usable = ($token !== '' && ($expires === 0 || $expires > time())) ? $token : null;

    $tokenUrl = rtrim((string) $this->config->get('token_url'), '/');
    if (empty($tokenUrl)) {
      $this->logger->error('Kelpgate OAuth2 token URL not configured.');
      return $usable;
    }
    if (!self::isSecureUrl($tokenUrl)) {
      $this->logger->error('Kelpgate OAuth2 token URL must use https; refusing to send credentials.');
      return null;
    }

    $this->cache->set($lock, 1, time() + 15);
    try {
      $response = $this->httpClient->request('POST', $tokenUrl, [
        'auth' => [$clientId, $clientSecret],
        'form_params' => [
          'grant_type' => 'client_credentials',
          'scope'      => 'scan',
        ],
        'timeout' => 15,
      ]);

      $data = json_decode((string) $response->getBody(), true);
      if (!empty($data['access_token'])) {
        $fresh = $data['access_token'];
        $expiresIn = (int) ($data['expires_in'] ?? 900);
        // Keep the entry until the token really expires; the refresh-ahead window replaces the
        // old 60-second early expiry.
        $this->cache->set($cid, ['t' => $fresh, 'e' => time() + $expiresIn], time() + max(60, $expiresIn));
        return $fresh;
      }
    }
    catch (\Exception $e) {
      $this->logger->error('OAuth2 token fetch failed: @err', ['@err' => $e->getMessage()]);
    }
    finally {
      $this->cache->delete($lock);
    }

    return $usable;
  }

  /**
   * Credentials and file contents travel to these endpoints, so they must use TLS. Plain http is
   * accepted only for loopback (local development).
   */
  public static function isSecureUrl(string $url): bool {
    $parts = parse_url($url);
    if (empty($parts['scheme']) || empty($parts['host'])) {
      return FALSE;
    }
    $scheme = strtolower($parts['scheme']);
    if ($scheme === 'https') {
      return TRUE;
    }
    return $scheme === 'http' && in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]', '::1'], TRUE);
  }

  /**
   * Drops the cached OAuth2 token (after a 401: revoked or rotated).
   */
  protected function forgetToken(): void {
    $this->cache->delete('kelpgate_oauth_token_' . md5(trim((string) $this->config->get('client_id'))));
  }

  /**
   * POSTs the file. http_errors is off on purpose: Kelpgate answers INFECTED with HTTP 406, and
   * Guzzle would otherwise throw before the verdict in the body can be read.
   */
  protected function postFile(string $url, string $token, string $realPath, string $filename, int $timeout) {
    $handle = fopen($realPath, 'r');
    if ($handle === FALSE) {
      throw new \RuntimeException('Cannot open the file for scanning.');
    }
    try {
      return $this->httpClient->request('POST', $url, [
        'headers' => ['Authorization' => 'Bearer ' . $token],
        'timeout' => $timeout,
        'http_errors' => FALSE,
        'multipart' => [[
          'name'     => 'file',
          'contents' => $handle,
          'filename' => $filename,
        ]],
      ]);
    }
    finally {
      if (is_resource($handle)) {
        fclose($handle);
      }
    }
  }

  /**
   * Checks the health of the Kelpgate API.
   */
  public function checkHealth(): array {
    $apiUrl = rtrim((string) $this->config->get('api_url'), '/');
    if (empty($apiUrl)) {
      return [
        'healthy' => false,
        'code'    => 0,
        'error'   => 'Scanner API endpoint is not configured.',
      ];
    }
    $token = $this->getAccessToken();
    $headers = [];
    if (!empty($token)) {
      $headers['Authorization'] = 'Bearer ' . $token;
    }

    try {
      $response = $this->httpClient->request('GET', $apiUrl . '/api/v1/health', [
        'headers' => $headers,
        'timeout' => 5,
      ]);
      return [
        'healthy' => ($response->getStatusCode() === 200),
        'code'    => $response->getStatusCode(),
      ];
    }
    catch (\Exception $e) {
      return [
        'healthy' => false,
        'code'    => 0,
        'error'   => $e->getMessage(),
      ];
    }
  }

  /**
   * Scans a Drupal FileInterface entity.
   */
  public function scanFile(FileInterface $file): array {
    $uri = $file->getFileUri();
    $realPath = \Drupal::service('file_system')->realpath($uri);

    if (!$realPath || !file_exists($realPath) || !is_readable($realPath)) {
      $this->logger->warning('Cannot read local file for Kelpgate scanning: @path', ['@path' => $uri]);
      return [
        'clean'     => false,
        'signature' => 'FILE_UNREADABLE',
      ];
    }

    $failAction = $this->config->get('fail_action') ?: 'block';

    $fileSize = filesize($realPath);
    $maxBytes = ((int) ($this->config->get('max_scan_mb') ?: 50)) * 1024 * 1024;
    if ($fileSize > $maxBytes) {
      // Oversized files must not bypass the scanner: they follow the failure policy
      // (rejected by default, accepted only when the admin chose fail-open).
      $this->logger->warning('File @file exceeds the maximum scan size and was @verdict.', [
        '@file' => $file->getFilename(),
        '@verdict' => $failAction === 'allow' ? 'accepted unscanned (fail-open)' : 'rejected (fail-closed)',
      ]);
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => 'FILE_TOO_LARGE',
      ];
    }

    $apiUrl = rtrim((string) $this->config->get('api_url'), '/');
    if (empty($apiUrl)) {
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => 'NOT_CONFIGURED',
      ];
    }
    $timeout = (int) ($this->config->get('timeout_seconds') ?: 45);
    if (!self::isSecureUrl($apiUrl)) {
      $this->logger->error('Kelpgate API URL must use https; the file was not sent.');
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => 'INSECURE_ENDPOINT',
      ];
    }
    $token = $this->getAccessToken();

    if (!$token) {
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => 'AUTH_FAILED',
      ];
    }

    $endpoint = '/api/v1/scan/file';

    try {
      $response = $this->postFile($apiUrl . $endpoint, $token, $realPath, $file->getFilename(), $timeout);

      // A revoked or rotated token would keep failing until the cached copy expires: drop it and
      // retry once with a fresh one.
      if ($response->getStatusCode() === 401 && ($this->config->get('auth_mode') ?: 'oauth2') !== 'token') {
        $this->forgetToken();
        $fresh = $this->getAccessToken();
        if ($fresh) {
          $response = $this->postFile($apiUrl . $endpoint, $fresh, $realPath, $file->getFilename(), $timeout);
        }
      }

      $statusCode = $response->getStatusCode();
      $body = json_decode((string) $response->getBody(), true);

      if ($statusCode === 200 && is_array($body) && isset($body['av-status']) && $body['av-status'] === 'CLEAN') {
        $this->logger->info('Kelpgate scan CLEAN for file @filename (SHA256: @sha)', [
          '@filename' => $file->getFilename(),
          '@sha'      => $body['sha256'] ?? 'n/a',
        ]);
        return [
          'clean'     => true,
          'signature' => 'CLEAN',
          'sha256'    => $body['sha256'] ?? '',
        ];
      }

      if (is_array($body) && isset($body['av-status']) && $body['av-status'] === 'INFECTED') {
        $sig = $body['av-signature'] ?? 'INFECTED';
        $this->logger->alert('MALWARE BLOCKED by Kelpgate on file @filename: @sig (SHA256: @sha)', [
          '@filename' => $file->getFilename(),
          '@sig'      => $sig,
          '@sha'      => $body['sha256'] ?? 'n/a',
        ]);
        return [
          'clean'     => false,
          'signature' => $sig,
          'sha256'    => $body['sha256'] ?? '',
        ];
      }

      $sig = $body['av-signature'] ?? ('HTTP_' . $statusCode);
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => $sig,
      ];
    }
    catch (\Throwable $e) {
      // Any transport failure (connect errors, timeouts, TLS, malformed responses) follows the
      // failure policy instead of bubbling up as an uncaught exception.
      $this->logger->error('Kelpgate scan error: @err', ['@err' => $e->getMessage()]);
      return [
        'clean'     => ($failAction === 'allow'),
        'signature' => 'SERVICE_UNREACHABLE',
      ];
    }
  }

  /**
   * Formats raw scanner output into clean, standardized commercial threat names.
   *
   * @param string $raw
   *   Raw signature string from API.
   *
   * @return string
   *   Clean, formatted threat name.
   */
  public static function formatThreatSignature(string $raw): string {
    if (empty($raw)) {
      return 'Threat Detected';
    }

    if (stripos($raw, 'eicar') !== false) {
      return 'EICAR-Standard-AV-Test-Signature';
    }

    $cleaned = preg_replace('/\b(ClamAV|YARA|Maldet|MalwareBazaar|Kelpgate_CoreSense|Kelpgate_PatternEngine|Kelpgate_WebShield|Kelpgate_CloudIntel|CoreSense|PatternEngine|WebShield|CloudIntel)\s*:\s*/i', '', $raw);
    $cleaned = str_ireplace('{HEX}', '', $cleaned);
    $cleaned = preg_replace('/\.UNOFFICIAL\b/i', '', $cleaned);
    $cleaned = preg_replace('/\.Hit\b/i', '', $cleaned);

    $parts = array_map('trim', explode('|', $cleaned));
    $unique = [];
    foreach ($parts as $p) {
      $sub = array_map('trim', explode(',', $p));
      foreach ($sub as $s) {
        if (!empty($s) && !in_array($s, $unique, true)) {
          $unique[] = $s;
        }
      }
    }

    if (empty($unique)) {
      return 'Threat Detected';
    }

    return implode(' · ', array_slice($unique, 0, 2));
  }

}
