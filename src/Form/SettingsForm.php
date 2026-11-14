<?php

namespace Drupal\kelpgate\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configure Kelpgate OAuth2 settings for this site.
 */
class SettingsForm extends ConfigFormBase {

  /**
   * The Kelpgate scanner service.
   *
   * @var \Drupal\kelpgate\Scanner\KelpgateScanner
   */
  protected $scanner;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->scanner = $container->get('kelpgate.scanner');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'kelpgate_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['kelpgate.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('kelpgate.settings');
    $health = $this->scanner->checkHealth();

    if ($health['healthy']) {
      $this->messenger()->addStatus($this->t('Kelpgate service is connected and healthy.'));
    }
    else {
      $this->messenger()->addWarning($this->t('Kelpgate service is currently unreachable or unauthenticated: @err', [
        '@err' => $health['error'] ?? ('HTTP ' . $health['code']),
      ]));
    }

    $form['enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enable Kelpgate malware scanning on file uploads'),
      '#default_value' => $config->get('enabled'),
    ];

    $form['api_url'] = [
      '#type' => 'url',
      '#title' => $this->t('Kelpgate API Endpoint'),
      '#default_value' => $config->get('api_url') ?: '',
      '#attributes' => ['placeholder' => 'https://api.your-kelpgate-domain.com'],
      '#description' => $this->t('The base URL of your Kelpgate REST API instance.'),
      '#required' => TRUE,
    ];

    $form['auth_mode'] = [
      '#type' => 'select',
      '#title' => $this->t('Authentication Mode'),
      '#options' => [
        'oauth2' => $this->t('OAuth2 Client Credentials (Recommended)'),
        'token'  => $this->t('Static Bearer Token'),
      ],
      '#default_value' => $config->get('auth_mode') ?: 'oauth2',
    ];

    $form['token_url'] = [
      '#type' => 'url',
      '#title' => $this->t('OAuth2 Token URL'),
      '#default_value' => $config->get('token_url') ?: '',
      '#attributes' => ['placeholder' => 'https://auth.your-kelpgate-domain.com/oauth2/token'],
      '#description' => $this->t('The OAuth 2.0 token endpoint for client credentials authentication.'),
    ];

    $form['client_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('OAuth2 Client ID'),
      '#default_value' => $config->get('client_id') ?: '',
      '#description' => $this->t('The Client ID issued from your Kelpgate Console.'),
    ];

    $form['client_secret'] = [
      '#type' => 'password',
      '#title' => $this->t('OAuth2 Client Secret'),
      '#default_value' => $config->get('client_secret') ?: '',
      '#description' => $this->t('Leave blank to keep the current secret, or enter a new one. It is stored in the database (State), not in exported config. To keep it out of the database as well, set $settings[\'kelpgate_client_secret\'] in settings.php, which takes precedence.'),
    ];

    $form['fail_action'] = [
      '#type' => 'radios',
      '#title' => $this->t('Scanner Failure Policy'),
      '#options' => [
        'block' => $this->t('Fail-Closed: Block file upload if scanner is unreachable (Recommended)'),
        'allow' => $this->t('Fail-Open: Allow file upload if scanner is unreachable'),
      ],
      '#default_value' => $config->get('fail_action') ?: 'block',
    ];

    $form['max_mb'] = [
      '#type' => 'number',
      '#title' => $this->t('Maximum Scan Size (MB)'),
      '#default_value' => $config->get('max_mb') ?: 50,
      '#min' => 1,
      '#max' => 500,
      '#description' => $this->t('Files larger than this are not sent to the scanner. They are rejected when the failure action is "block" and accepted unscanned only when it is "allow".'),
    ];

    $form['timeout_seconds'] = [
      '#type' => 'number',
      '#title' => $this->t('Request Timeout (seconds)'),
      '#default_value' => $config->get('timeout_seconds') ?: 45,
      '#min' => 5,
      '#max' => 300,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $config = $this->config('kelpgate.settings');
    $config
      ->set('enabled', (bool) $form_state->getValue('enabled'))
      ->set('api_url', rtrim($form_state->getValue('api_url'), '/'))
      ->set('auth_mode', $form_state->getValue('auth_mode'))
      ->set('token_url', rtrim($form_state->getValue('token_url'), '/'))
      ->set('client_id', trim($form_state->getValue('client_id')))
      ->set('fail_action', $form_state->getValue('fail_action'))
      ->set('max_mb', (int) $form_state->getValue('max_mb'))
      ->set('timeout_seconds', (int) $form_state->getValue('timeout_seconds'));

    // The secret goes to the State API (database only), never into config: config is exported with
    // `drush config:export` and normally committed. A value in settings.php always wins.
    $secret = trim($form_state->getValue('client_secret'));
    if (!empty($secret)) {
      \Drupal::state()->set('kelpgate.client_secret', $secret);
    }
    // Earlier versions kept the secret in config: move it to State before removing it, so saving the
    // form without retyping the secret does not lose it.
    $legacy = trim((string) $config->get('client_secret'));
    if (empty($secret) && !empty($legacy) && empty(\Drupal::state()->get('kelpgate.client_secret'))) {
      \Drupal::state()->set('kelpgate.client_secret', $legacy);
    }
    $config->set('client_secret', '');

    $config->save();
    parent::submitForm($form, $form_state);
  }

}
