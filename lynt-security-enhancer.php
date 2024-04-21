<?php
/**
 * Plugin Name: Lynt Security Enhancer
 * Description: Lynt Security enhnacements for WordPress
 * Plugin URI:  https://github.com/lynt-smitka/WP-Security-Enhancer
 * Author:      Vladimir Smitka
 * Author URI:  https://smitka.me/
 * License:     GNU General Public License v3 or later
 * License URI: http://www.gnu.org/licenses/gpl-3.0.html
 */

defined('ABSPATH') or die('nothing here');


$enabled_features = [

  'bcrypt_hash' => true,
  'bcrypt_rehash_passwords' => true,
  'filter_rest_users' => true,
  'filter_rest_comments' => true,
  'failed_login_401' => true,
  'limit_password_length' => true,
  'auto_invalidate_sessions' => false,
  'admin_actions_check_referrer' => false,

];

class Lynt_Enhancer
{

  private static $instance = null;
  private $enabled_features;
  public $bcrypt_rounds = 12;
  public $max_password_length = 150;

  private function __construct($enabled_features)
  {
    $this->enabled_features = $enabled_features;
    $this->add_hooks();
  }

  public static function get_instance($enabled_features)
  {
    if (null === self::$instance) {
      self::$instance = new self($enabled_features);
    }
    return self::$instance;
  }


  private function add_hooks()
  {



    foreach ($this->enabled_features as $feature => $enabled) {
      if ($enabled) {
        switch ($feature) {

          case 'bcrypt_hash':
            $this->bcrypt_hash();
            break;
          case 'bcrypt_rehash_passwords':
            add_action('wp_authenticate_user', array($this, 'bcrypt_rehash_passwords'), 10, 2);
            break;
          case 'filter_rest_users':
            add_filter('rest_prepare_user', array($this, 'remove_sensitive_data_from_rest_user'));
            break;
          case 'filter_rest_comments':
            add_filter('rest_prepare_comment', array($this, 'remove_sensitive_data_from_rest_comment'));
            break;
          case 'failed_login_401':
            add_action('wp_login_failed', array($this, 'failed_login_401'));
            break;
          case 'limit_password_length':
            add_filter('wp_authenticate_user', array($this, 'limit_password_length'), 10, 2);
            break;
          case 'auto_invalidate_sessions':
            add_action('init', array($this, 'new_ip_invalidate_sessions'));
            break;
          case 'admin_actions_check_referrer':
            add_action('admin_init', array($this, 'admin_actions_check_referrer'));
            break;

        }
      }
    }
  }


  public function bcrypt_hash()
  {
    global $wp_hasher;

    if (empty($wp_hasher)) {
      require_once (ABSPATH . WPINC . '/class-phpass.php');
      $wp_hasher = new PasswordHash($this->bcrypt_rounds, false);
    }
  }


  public function bcrypt_rehash_passwords($user, $password)
  {
    if (!$user instanceof WP_User) {
      return $user;
    }
    $stored_hash = $user->data->user_pass;
    if (strpos($stored_hash, '$2a$') === 0) {
      return $user;
    }
    wp_set_password($password, $user->ID);
    return $user;
  }



  public function remove_sensitive_data_from_rest_user($response)
  {
    if (!current_user_can('list_users')) {
      $data = $response->get_data();
      if (preg_replace('/[\W]+/', '', $data['name']) == preg_replace('/[\W]+/', '', $data['slug']))
        $data['name'] = "Author";
      unset($data['link']);
      unset($data['slug']);
      unset($data['avatar_urls']);
      $response->set_data($data);
    }
    return $response;
  }

  public function remove_sensitive_data_from_rest_comment($response)
  {
    if (!current_user_can('list_users')) {
      $data = $response->get_data();
      unset($data['author_avatar_urls']);
      $response->set_data($data);
    }
    return $response;
  }

  public function failed_login_401()
  {
    status_header(401);
  }


  public function limit_password_length($user, $password)
  {
    if (strlen($password) > $this->max_password_length) {
      $username = esc_html($_POST['log']);
      return new WP_Error(
        'incorrect_password',
        sprintf(
          __('<strong>Error:</strong> The password you entered for the username %s is incorrect.'),
          '<strong>' . $username . '</strong>'
        ) .
        ' <a href="' . wp_lostpassword_url() . '">' .
        __('Lost your password?') .
        '</a>'
      );

    }

    return $user;
  }

  public function new_ip_invalidate_sessions()
  {
    if (is_user_logged_in()) {
      $user_id = get_current_user_id();
      $current_ip = $_SERVER['REMOTE_ADDR'];

      $session_tokens = get_user_meta($user_id, 'session_tokens', true);
      $sessions = maybe_unserialize($session_tokens);

      if (is_array($sessions)) {
        foreach ($sessions as $token => $session) {
          if ($session['ip'] !== $current_ip) {
            WP_Session_Tokens::get_instance($user_id)->destroy_all();
            break;
          }
        }
      }

    }
  }


  public function admin_actions_check_referrer()
  {
    if (is_admin() && !defined('DOING_AJAX') && !defined('DOING_CRON')) {
      if (!isset($_SERVER['HTTP_SEC_FETCH_USER']) || $_SERVER['HTTP_SEC_FETCH_USER'] !== "?1") {
        die();
      }
      if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
        if (strpos($referer, admin_url()) === false) {
          die();
        }
      }
    }
  }


}


// Initialize enhancer with enabled features
$lynt_enhancer = Lynt_Enhancer::get_instance($enabled_features);
