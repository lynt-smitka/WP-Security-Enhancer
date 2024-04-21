<?php
/**
 * Plugin Name: Lynt Security Enhancer - Audit Log
 * Description: Lynt Security enhnacements for WordPress
 * Plugin URI:  https://github.com/lynt-smitka/WP-Security-Enhancer
 * Author:      Vladimir Smitka
 * Author URI:  https://smitka.me/
 * License:     GNU General Public License v3 or later
 * License URI: http://www.gnu.org/licenses/gpl-3.0.html
 */

 defined( 'ABSPATH' ) or die( 'nothing here' );

 $events_to_log = [
    // User events
    'user_create' => true,
    'user_delete' => true,
    'user_update' => true,
    'user_role_change' => true,
    'user_password_reset' => true,
    'user_lost_password_request' => true,
    'user_login' => true,
    'user_logout' => true,
    'user_login_failed' => false,

    // App passwords events
    'app_password_create' => true,
    'app_password_delete' => true,

    // Post events
    'post_status_change' => true,
    'post_update' => true,

    // Plugin and theme events
    'plugin_activation' => true,
    'plugin_deactivation' => true,
    'plugin_deletion' => true,
    'theme_deletion' => true,
    'theme_switch' => true,
    'wp_update' => true,


    // File and media events
    'media_upload' => true,
    'file_edit' => true,

    // WP core events
    'wp_request' => false,
    'wp_error' => false,
    'wp_mail' => false,

    // Cron events
    'cron_schedule' => false,
    'cron_unscheduld' => false,

    // Option events
    'option_add' => false,
    'option_update' => false,
    'option_delete' => false

];

class Lynt_Event_Logger
{
    private static $instance = null;
    private $log_events;
    private $log_type;
    private $log_destination;
    private $log_emails;

    public $prefix = "WP Audit: ";


    private function __construct($events_to_log, $log = 'error_log', $log_emails = true)
    {
        $this->log_events = $events_to_log;
        $this->set_log_properties($log, $log_emails);
        $this->add_hooks();
    }

    public static function get_instance($events_to_log = [], $log = 'error_log', $log_emails = true)
    {
        if (null === self::$instance) {
            self::$instance = new self($events_to_log, $log, $log_emails);
        }
        return self::$instance;
    }

    private function set_log_properties($log, $log_emails)
    {
        if ($log === 'syslog') {
            $this->log_type = 'syslog';
            $this->log_destination = '';
        } elseif ($log === 'error_log' || $log === '') {
            $this->log_type = 'error_log';
            $this->log_destination = '';
        } else {
            $this->log_type = 'file';
            $this->log_destination = realpath($log);
        }
        $this->log_emails = $log_emails;
    }

    private function add_hooks()
    {
        foreach ($this->log_events as $event => $enabled) {
            if ($enabled) {
                switch ($event) {
                    case 'user_create':
                        add_action('user_register', array($this, 'log_user_create'), 10, 1);
                        break;
                    case 'user_delete':
                        add_action('deleted_user', array($this, 'log_user_delete'), 10, 3);
                        break;
                    case 'user_update':
                        add_action('profile_update', array($this, 'log_user_update'), 10, 3);
                        break;
                    case 'user_role_change':
                        add_action('set_user_role', array($this, 'log_user_role_change'), 10, 3);
                        break;
                    case 'user_password_reset':
                        add_action('after_password_reset', array($this, 'log_password_reset'), 10, 2);
                        break;
                    case 'user_lost_password_request':
                        add_action('lostpassword_post', array($this, 'log_lost_password_request'), 10, 2);
                        break;
                    case 'user_login':
                        add_action('wp_login', array($this, 'log_user_login'), 10, 2);
                        break;
                    case 'user_logout':
                        add_action('wp_logout', array($this, 'log_user_logout'), 10, 2);
                        break;
                    case 'user_login_failed':
                        add_action('wp_login_failed', array($this, 'log_user_login_failed'));
                        break;

                    case 'app_password_create':
                        add_action('wp_create_application_password', array($this, 'log_app_password_create'), 10, 2);
                        break;
                    case 'app_password_delete':
                        add_action('wp_delete_application_password', array($this, 'log_app_password_delete'), 10, 2);
                        break;

                    case 'post_status_change':
                        add_action('transition_post_status', array($this, 'log_post_status_change'), 10, 3);
                        break;
                    case 'post_update':
                        add_action('save_post', array($this, 'log_post_save'), 10, 3);
                        break;

                    case 'plugin_activation':
                        add_action('activated_plugin', array($this, 'log_plugin_activation'), 10, 2);
                        break;
                    case 'plugin_deactivation':
                        add_action('deactivated_plugin', array($this, 'log_plugin_deactivation'), 10, 2);
                        break;
                    case 'plugin_deletion':
                        add_action('delete_plugin', array($this, 'log_plugin_deletion'), 10, 1);
                        break;
                    case 'theme_deletion':
                        add_action('delete_theme', array($this, 'log_theme_deletion'), 10, 1);
                        break;
                    case 'theme_switch':
                        add_action('switch_theme', array($this, 'log_theme_switch'), 10, 3);
                        break;
                    case 'wp_update':
                        add_action('upgrader_process_complete', array($this, 'log_wp_update'), 10, 2);
                        break;

                    case 'media_upload':
                        add_action('add_attachment', array($this, 'log_media_upload'), 10, 1);
                        break;
                    case 'file_edit':
                        add_action('admin_init', array($this, 'log_file_edit'));
                        break;

                    case 'wp_request':
                        add_action('http_api_curl', array($this, 'log_wp_request'), 10, 3);
                        break;
                    case 'wp_error':
                        add_action('wp_error_added', array($this, 'log_wp_error'), 10, 4);
                        break;
                    case 'wp_mail':
                        add_filter('wp_mail', array($this, 'log_wp_mail'), 10, 1);
                        break;

                    case 'cron_schedule':
                        add_action('schedule_event', array($this, 'log_cron_scheduled'), 10, 1);
                        break;
                    case 'cron_unschedule':
                        add_action('unschedule_event', array($this, 'log_cron_unscheduled'), 10, 1);
                        break;

                    case 'option_add':
                        add_action('option_add', array($this, 'log_add_option'), 10, 2);
                        break;
                    case 'option_update':
                        add_action('option_update', array($this, 'log_update_option'), 10, 3);
                        break;
                    case 'option_delete':
                        add_action('option_delete', array($this, 'log_delete_option'), 10, 1);
                        break;


                }
            }
        }
    }

    // Implementing specific logging methods for each event
    public function log($type, $message, $details = null)
    {

        $user_ip = $_SERVER['REMOTE_ADDR'];
        $user_name = 'no-user';
        $user_id = get_current_user_id(); // TODO: handle login/logout
        $user_privileges = 'none';

        if ($user_id > 0) {
            $user = get_userdata($user_id);
            $user_name = $user->user_login;
            if (user_can($user_id, 'edit_posts'))
                $user_privileges = 'small';
            if (user_can($user_id, 'publish_posts'))
                $user_privileges = 'medium';
            if (user_can($user_id, 'create_users'))
                $user_privileges = 'high';
        }

        $domain = wp_parse_url(home_url())['host'];
        $timestamp = time();

        $type = sanitize_text_field($type);
        $message = sanitize_text_field($message);

        $log = json_encode([
            'type' => $type,
            'site' => $domain,
            'timestamp' => $timestamp,
            'user_ip' => $user_ip,
            'user_id' => $user_id,
            'user_name' => $user_name,
            'user_privileges' => $user_privileges,
            'message' => $message,
            'details' => $details
        ]);

        if ($this->log_type === 'syslog') {
            syslog(LOG_INFO, $log);
        } elseif ($this->log_type === 'error_log') {
            error_log($this->prefix . $log);
        } else {
            error_log($this->prefix . $log, 3, $this->log_destination);
        }
    }


    public function log_user_create($user_id)
    {

        $user = get_userdata($user_id);

        if ($this->log_emails) {
            $user_email = $user->user_email;
        } else {
            $user_email = "redacted";
        }

        $details = array(
            'user_id' => $user_id,
            'user_name' => $user->user_login,
            'email' => $user_email,
            'roles' => implode(', ', $user->roles)
        );

        $this->log('user_created', "User account {$user->user_login} created", $details);
    }

    public function log_user_update($user_id, $old_user_data, $user_data)
    {

        $user = get_userdata($user_id);

        $details = array(
            'user_id' => $user_id,
            'user_name' => $user->user_login
        );

        $this->log('user_updated', "User account {$user->user_login} updated", $details);
    }

    public function log_user_delete($id, $reassign, $user)
    {

        $details = array(
            'user_id' => $user->ID,
            'user_name' => $user->user_login,
        );

        $this->log('user_updated', "User account {$user->user_login} deleted", $details);
    }



    public function log_user_role_change($user_id, $role, $old_roles)
    {

        $user = get_userdata($user_id);

        $details = array(
            'user_id' => $user_id,
            'user_name' => $user->user_login,
            'new_role' => $role,
            'old_roles' => $old_roles
        );

        $this->log('user_role_changed', "User role of user {$user->user_login} changed to {$role}", $details);
    }

    public function log_password_reset($user, $new_pass)
    {

        $details = array(
            'user_id' => $user->ID,
            'user_name' => $user->user_login
        );

        $this->log('password_reset', "Password reset for user {$user->user_login}", $details);
    }


    public function log_lost_password_request($errors, $user = null)
    {

        if (is_null($user)) {
            return;
        }

        $details = array(
            'user_id' => $user->ID,
            'user_name' => $user->user_login
        );

        $this->log('lost_password_request', "Lost password form send for user {$user->user_login}", $details);
    }



    public function log_user_login($user_login, $user)
    {

        $details = array(
            'user_id' => $user->ID,
            'user_login' => $user_login,
            'roles' => $user->roles
        );

        $this->log('user_login_success', "User {$user->user_login} logged in", $details);
    }

    public function log_user_logout($user_id)
    {

        $user = get_userdata($user_id);

        $details = array(
            'user_id' => $user_id,
            'user_name' => $user->user_login,
            'roles' => $user->roles
        );

        $this->log('user_logout', "User {$user->user_login} logged out", $details);
    }


    public function log_user_login_failed($username)
    {

        $user_id = username_exists($username);

        $details = array(
            'username' => $username,
            'user_exists' => $user_id
        );

        $existing = $user_id ? "real" : "fake";

        $this->log('user_login_failed', "Unsuccessful login attempt for {$existing} user {$username}", $details);
    }

    public function log_app_password_create($user_id, $app_password)
    {

        $user = get_userdata($user_id);

        $details = array(
            'user_id' => $user_id,
            'app_password_name' => $app_password['name']
        );

        $this->log('app_password_create', "User {$user->user_login} created App password {$app_password['name']}", $details);
    }

    public function log_app_password_delete($user_id, $app_password)
    {

        $user = get_userdata($user_id);

        $details = array(
            'user_id' => $user_id,
            'app_password_name' => $app_password['name']
        );
        $this->log('app_password_delete', "User {$user->user_login} deleted App password {$app_password['name']}", $details);
    }


    public function log_post_status_change($new_status, $old_status, $post)
    {

        if ('publish' === $new_status && 'publish' !== $old_status) {

            $details = array(
                'post_id' => $post->ID,
                'post_type' => $post->post_type,
                'post_title' => $post->post_title,
                'old_status' => $old_status,
                'new_status' => $new_status
            );

            $this->log('post_status_change', "Changed status of {$post->post_type} {$post->post_title} to {$new_status}", $details);
        }
    }


    public function log_post_save($post_id, $post, $update)
    {

        if ($post->post_type !== 'revision' && $post->post_type !== 'auto-draft') {

            $action = $update ? 'post_update' : 'post_create';

            $origin = "system";
            if (defined('REST_REQUEST') && REST_REQUEST)
                $origin = "rest-api";
            if (isset($_POST['action']))
                $origin = "post";

            $details = array(
                'post_id' => $post_id,
                'post_type' => $post->post_type,
                'post_title' => $post->post_title,
                'post_status' => $post->post_status,
                'origin' => $origin,
            );

            $this->log($action, "Post {$post->post_title} of type {$post->post_type} was saved with status {$post->post_status}", $details);
        }
    }


    public function log_plugin_activation($plugin, $network_wide)
    {

        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);

        $details = array(
            'plugin' => $plugin,
            'plugin_name' => $plugin_data['Name'],
            'plugin_version' => $plugin_data['Version'],
        );

        $this->log('plugin_activate', "Plugin {$details['plugin_name']} activated", $details);
    }

    public function log_plugin_deactivation($plugin, $network_wide)
    {

        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);

        $details = array(
            'plugin' => $plugin,
            'plugin_name' => $plugin_data['Name'],
            'plugin_version' => $plugin_data['Version'],
        );

        $this->log('plugin_deactivate', "Plugin {$details['plugin_name']} deactivated", $details);
    }



    public function log_plugin_deletion($plugin)
    {


        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
        $details = array(
            'plugin' => $plugin,
            'plugin_name' => $plugin_data['Name'],
            'plugin_version' => $plugin_data['Version'],
        );

        $this->log('plugin_delete', "Plugin {$details['plugin_name']} deleted", $details);
    }



    public function log_theme_deletion($stylesheet)
    {
        $this->log('theme_deleted', 'Theme deleted', ['theme' => $stylesheet]);
    }

    public function log_theme_switch($new_name, $new_theme, $old_theme)
    {
        $details = array(
            'new_theme' => $new_theme['Name'],
            'new_theme_version' => $new_theme['Version'],
            'old_theme' => $old_theme['Name'],
            'old_theme_version' => $old_theme['Version'],
        );
        $this->log('theme_switch', "Theme changed to {$new_theme['Name']}", $details);
    }


    public function log_wp_update($upgrader, $options)
    {
        $action = $options['action'];
        $type = $options['type'];

        if ('install' === $action) {
            if ('plugin' === $type) {

                $plugin = $upgrader->plugin_info();
                $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
                $details = array(
                    'plugin' => $plugin,
                    'plugin_name' => $plugin_data['Name'],
                    'plugin_version' => $plugin_data['Version']
                );

                $this->log('plugin_install', "New plugin {$plugin_data['Name']} installed", $details);

            } elseif ('theme' === $type) {

                $theme = $upgrader->theme_info();
                $details = array(
                    'theme_name' => $theme->Name,
                    'theme_version' => $theme->Version
                );

                $this->log('theme_install', "New theme {$theme->Name} installed", $details);
            }

        } elseif ('update' === $action) {
            if ('plugin' === $type) {
                foreach ($options['plugins'] as $plugin) {

                    $plugin = $upgrader->plugin_info();
                    $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
                    $details = array(
                        'plugin' => $plugin,
                        'plugin_name' => $plugin_data['Name'],
                        'plugin_version' => $plugin_data['Version']
                    );

                    $this->log('plugin_updade', "Plugin {$plugin_data['Name']} updated to {$plugin_data['Version']}", $details);
                }
            } elseif ('theme' === $type) {
                foreach ($options['themes'] as $theme_css) {
                    $theme = wp_get_theme($theme_css);
                    $details = array(
                        'theme_name' => $theme->Name,
                        'theme_version' => $theme->Version
                    );

                    $this->log('theme_update', "Theme {$theme->Name} updated to {$theme->Version}", $details);
                }
            } elseif ('core' === $type) {
                global $wp_version;
                $this->log('core_update', "WP Core updated to version {$wp_version}");

            }
        }
    }


    public function log_media_upload($post_ID)
    {
        $file = get_attached_file($post_ID);
        $file_name = basename($file);

        $details = array(
            'post_id' => $post_ID,
            'file_path' => $file,
        );

        $this->log('media_uploaded', "File {$file_name} uploaded to media gallery", $details);
    }

    public function log_file_edit()
    {
        if (isset($_POST['action']) && $_POST['action'] === 'edit-theme-plugin-file' && isset($_POST['newcontent'])) {
            $file = isset($_POST['file']) ? $_POST['file'] : '';
            $file_name = basename($file);
            $component_type = isset($_POST['theme']) ? 'theme' : (isset($_POST['plugin']) ? 'plugin' : '');
            $component_name = isset($_POST['theme']) ? $_POST['theme'] : (isset($_POST['plugin']) ? dirname($_POST['plugin']) : '');

            $details = array(
                'file' => $file,
                'component' => $component_name
            );

            $this->log($component_type . '_file_edited', "File {$file_name} from {$component_type} {$component_name} edited using the WP editor", $details);
        }
    }

    public function log_wp_request($handle, $parsed_args, $url)
    {
        $details = array(
            'url' => $url,
            'method' => isset($parsed_args['method']) ? $parsed_args['method'] : 'GET',
            //'body' => isset($parsed_args['body']) ? $parsed_args['body'] : 'No Body',
            //'headers' => isset($parsed_args['headers']) ? $parsed_args['headers'] : 'No Headers'
        );

        $this->log('http_request', "WP made HTTP {$details['method']} request to {$details['url']}", $details);
    }

    public function log_wp_error($code, $message, $data, $wp_error)
    {
        $details = array(
            'code' => $code,
            'message' => $message,
            'data' => $data,
            'wp_error_data' => $wp_error->get_error_data()
        );
        $this->log('wp_error', "WP_Error occured", $details);
    }

    public function log_wp_mail($args)
    {

        if ($this->log_emails) {
            $recipient = isset($args['to']) ? $args['to'] : 'No recipient';
        } else {
            $recipient = isset($args['to']) ? $args['to'] : 'No recipient';
            if (filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                list($username, $domain) = explode('@', $recipient);
                $recipient = 'redacted@' . $domain;
            } else {
                $recipient = 'redacted';
            }
        }

        $details = array(
            'recipient' => $recipient,
            'subject' => isset($args['subject']) ? $args['subject'] : 'No subject'
        );
        $this->log('wp_mail', "Email sent to {$recipient}", $details);
    }


    public function log_cron_scheduled($event)
    {
        if (!$event)
            return;
        $details = array(
            'hook' => $event->hook,
            'timestamp' => $event->timestamp,
            'schedule' => $event->schedule,
            'args' => json_encode($event->args)
        );
        $this->log('cron_scheduled', "New cron job {$details['hook']} scheduled", $details);
    }

    public function log_cron_unscheduled($event)
    {
        if (!$event)
            return;
        $details = array(
            'hook' => $event->hook,
            'timestamp' => $event->timestamp,
            'args' => json_encode($event->args)
        );
        $this->log('cron_unscheduled', "Cron job {$details['hook']} unscheduled", $details);
    }

    public function log_add_option($option, $value) {

        $details = array(
            'option' => $option,
            'value' => $value
        );

        $this->log('option_add', "New option {$option} added", $details);
    }

    public function log_update_option($option, $old_value, $new_value) {
        $details = array(
            "option"=> $option,
            "old_value" => $old_value,
            "new_value" => $new_value
        );
     
        if ($old_value !== $new_value) {
            $this->log("option_update", "Option {$option} updated", $details);
        }

    }

    public function log_delete_option($option) {
        $details = array(
            'option' => $option
        );

        $this->log('option_delete', "Option {$option} deleted", $details);
    }

}

// Initialize the logger with selected events to log
$lynt_logger = Lynt_Event_Logger::get_instance($events_to_log);
