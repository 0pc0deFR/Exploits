<?php

require_once ABSPATH . '/wp-admin/includes/misc.php';
require_once ABSPATH . '/wp-admin/includes/file.php';

/**
 * Plugin Name: Brute Force Login Protection
 * Plugin URI: http://wordpress.org/plugins/brute-force-login-protection/
 * Description: Protects your website against brute force login attacks using .htaccess
 * Text Domain: brute-force-login-protection
 * Author: Jan-Paul Kleemans
 * Author URI: http://profiles.wordpress.org/jan-paul-kleemans/
 * Version: 1.3
 * License: GPL2
 * 
 * Copyright 2014  Jan-Paul Kleemans
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as 
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
class BruteForceLoginProtection {

    private $__options;

    public function __construct() {
        //Default options
        $this->__setDefaultOptions();

        //Activation and deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        //Init hooks
        add_action('plugins_loaded', array($this, 'init'));
        add_action('admin_init', array($this, 'adminInit'));
        add_action('admin_menu', array($this, 'menuInit'));

        //Login hooks
        add_action('wp_login_failed', array($this, 'loginFailed'));
        add_action('wp_login', array($this, 'loginSucceeded'));

        //Auth cookie hooks
        add_action('auth_cookie_bad_username', array($this, 'loginFailed'));
        add_action('auth_cookie_bad_hash', array($this, 'loginFailed'));
    }

    /**
     * Called once any activated plugins have been loaded.
     * 
     * @return void
     */
    public function init() {
        //Load textdomain for i18n
        load_plugin_textdomain('brute-force-login-protection', false, dirname(plugin_basename(__FILE__)) . '/languages/');

        //Overrule default $__options with database options
        $this->__fillOptions();

        //Call checkRequirements to check for .htaccess errors
        add_action('admin_notices', array($this, 'showRequirementsErrors'));
    }

    /**
     * Called when a user accesses the admin area.
     * 
     * @return void
     */
    public function adminInit() {
        //Register plugin settings
        $this->__registerOptions();
    }

    /**
     * Called after the basic admin panel menu structure is in place.
     * 
     * @return void
     */
    public function menuInit() {
        //Add settings page to the Settings menu
        add_options_page(__('Brute Force Login Protection Settings', 'brute-force-login-protection'), 'Brute Force Login Protection', 'manage_options', 'brute-force-login-protection', array($this, 'showSettingsPage'));
    }

    /**
     * Called When the plugin is activated
     * Adds base lines to .htaccess and resets commented denies.
     * 
     * @return boolean
     */
    public function activate() {
        $lines = extract_from_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection');

        $insertion[] = '<Files "*">';
        $insertion[] = 'order allow,deny';
        foreach ($lines as $line) {
            if (substr($line, 0, 10) === "#deny from") {
                $insertion[] = 'deny from ' . substr($line, 11);
            }
        }
        $insertion[] = 'allow from all';
        $insertion[] = '</Files>';

        return insert_with_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection', $insertion);
    }

    /**
     * Called When the plugin is deactivated
     * Comments out all denies in .htaccess.
     * 
     * @return boolean
     */
    public function deactivate() {
        $deniedIPs = $this->__getDeniedIPs();

        foreach ($deniedIPs as $deniedIP) {
            $insertion[] = '#deny from ' . $deniedIP;
        }

        return insert_with_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection', $insertion);
    }

    /**
     * Checks requirements and shows errors
     * 
     * @return void
     */
    public function showRequirementsErrors() {
        $status = $this->__checkRequirements();

        if (!$status['found']) {
            $this->__showError(__('Brute Force Login Protection error: .htaccess file not found', 'brute-force-login-protection'));
        } elseif (!$status['readable']) {
            $this->__showError(__('Brute Force Login Protection error: .htaccess file not readable', 'brute-force-login-protection'));
        } elseif (!$status['writeable']) {
            $this->__showError(__('Brute Force Login Protection error: .htaccess file not writeable', 'brute-force-login-protection'));
        }
    }

    /**
     * Shows settings page and handles user actions.
     * 
     * @return void
     */
    public function showSettingsPage() {
        if (isset($_POST['IP'])) {
            $IP = filter_var($_POST['IP'], FILTER_VALIDATE_IP);

            if (isset($_POST['block'])) { //Manually block IP
                if ($IP && $this->__denyIP($IP)) {
                    $this->__showMessage(sprintf(__('IP %s blocked', 'brute-force-login-protection'), $IP));
                } else {
                    $this->__showError(sprintf(__('An error occurred while blocking IP %s', 'brute-force-login-protection'), $IP));
                }
            } elseif (isset($_POST['unblock'])) { //Unblock IP
                if ($IP && $this->__undenyIP($IP)) {
                    $this->__showMessage(sprintf(__('IP %s unblocked', 'brute-force-login-protection'), $IP));
                } else {
                    $this->__showError(sprintf(__('An error occurred while unblocking IP %s', 'brute-force-login-protection'), $IP));
                }
            }
        } elseif (isset($_POST['reset'])) {
            $this->__deleteOptions();
            $this->__setDefaultOptions();
            $this->__showMessage(sprintf(__('The Options have been successfully reset', 'brute-force-login-protection'), $IP));
        }

        include 'settings-page.php';
    }

    /**
     * Called when a user login has failed
     * Increase number of attempts for clients IP. Deny IP if max attempts is reached.
     * 
     * @return void
     */
    public function loginFailed() {
        $attempts = get_option('bflp_login_attempts');
        if (!is_array($attempts)) {
            $attempts = array();
            add_option('bflp_login_attempts', $attempts, '', 'no');
        }

        $IP = $this->__getClientIP();
        $denyIP = false;

        if ($IP && isset($attempts[$IP]) && $attempts[$IP]['time'] > (time() - ($this->__options['reset_time'] * 60))) {
            $attempts[$IP]['attempts'] ++;
            if ($attempts[$IP]['attempts'] >= $this->__options['allowed_attempts']) {
                $denyIP = true;
                unset($attempts[$IP]);
            } else {
                $attempts[$IP]['time'] = time();
            }
        } else {
            $attempts[$IP]['attempts'] = 1;
            $attempts[$IP]['time'] = time();
        }

        update_option('bflp_login_attempts', $attempts);

        if ($this->__options['inform_user']) {
            global $error;
            $remainingAttempts = $this->__options['allowed_attempts'] - $attempts[$IP]['attempts'];
            $error .= '<br />';
            $error .= sprintf(_n("%d attempt remaining.", "%d attempts remaining.", $remainingAttempts, 'brute-force-login-protection'), $remainingAttempts);
        }

        if ($denyIP) {
            $this->__denyIP($IP);
        }
    }

    /**
     * Called when a user has successfully logged in
     * Removes IP from bflp_login_attempts if exist.
     * 
     * @return void
     */
    public function loginSucceeded() {
        $attempts = get_option('bflp_login_attempts');
        if (is_array($attempts)) {
            $IP = $this->__getClientIP();
            if (isset($attempts[$IP])) {
                unset($attempts[$IP]);
                update_option('bflp_login_attempts', $attempts);
            }
        }
    }

    /**
     * Settings validation functions
     */

    /**
     * Validates bflp_allowed_attempts field.
     * 
     * @param mixed $input
     * @return int
     */
    public function validateAllowedAttempts($input) {
        if (is_numeric($input) && ($input >= 1 && $input <= 100)) {
            return $input;
        } else {
            add_settings_error('bflp_allowed_attempts', 'bflp_allowed_attempts', __('Allowed login attempts must be a number (between 1 and 100)', 'brute-force-login-protection'));
            return $this->__options['allowed_attempts'];
        }
    }

    /**
     * Validates bflp_reset_time field.
     * 
     * @param mixed $input
     * @return int
     */
    public function validateResetTime($input) {
        if (is_numeric($input) && $input >= 1) {
            return $input;
        } else {
            add_settings_error('bflp_reset_time', 'bflp_reset_time', __('Minutes before resetting must be a number (higher than 1)', 'brute-force-login-protection'));
            return $this->__options['reset_time'];
        }
    }

    /**
     * Private functions
     */

    /**
     * Checks if .htaccess file is found, readable and writeable.
     * 
     * @return array
     */
    public function __checkRequirements() {
        $status = array(
            'found' => false,
            'readable' => false,
            'writeable' => false
        );

        $htaccessPath = $this->__options['htaccess_dir'] . '/.htaccess';

        if (file_exists($htaccessPath)) { //File found
            $status['found'] = true;
        }
        if (is_readable($htaccessPath)) { //File readable
            $status['readable'] = true;
        }
        if (is_writeable($htaccessPath)) { //File writeable
            $status['writeable'] = true;
        }

        return $status;
    }

    /**
     * Registers options (settings).
     * 
     * @return void
     */
    private function __registerOptions() {
        register_setting('brute-force-login-protection', 'bflp_allowed_attempts', array($this, 'validateAllowedAttempts'));
        register_setting('brute-force-login-protection', 'bflp_reset_time', array($this, 'validateResetTime'));
        register_setting('brute-force-login-protection', 'bflp_inform_user');
        register_setting('brute-force-login-protection', 'bflp_htaccess_dir');
    }

    /**
     * Fills options with value (from database).
     * 
     * @return void
     */
    private function __fillOptions() {
        $this->__options['allowed_attempts'] = get_option('bflp_allowed_attempts', $this->__options['allowed_attempts']);
        $this->__options['reset_time'] = get_option('bflp_reset_time', $this->__options['reset_time']);
        $this->__options['inform_user'] = get_option('bflp_inform_user', $this->__options['inform_user']);
        $this->__options['htaccess_dir'] = get_option('bflp_htaccess_dir', $this->__options['htaccess_dir']);
    }

    /**
     * Fills options with default value.
     * 
     * @return void
     */
    private function __setDefaultOptions() {
        $this->__options = array(
            'allowed_attempts' => 20, //Allowed login attempts before deny,
            'reset_time' => 60, //Minutes before resetting login attempts count
            'inform_user' => true, //Inform user about remaining login attempts on login page
            'htaccess_dir' => get_home_path() //.htaccess file location
        );
    }

    /**
     * Deletes options from database
     * 
     * @return void
     */
    private function __deleteOptions() {
        delete_option('bflp_allowed_attempts');
        delete_option('bflp_reset_time');
        delete_option('bflp_inform_user');
        delete_option('bflp_htaccess_dir');
    }

    /**
     * Returs array of denied IP addresses from .htaccess.
     * 
     * @return array
     */
    private function __getDeniedIPs() {
        $lines = extract_from_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection');

        $deniedIPs = array();
        foreach ($lines as $line) {
            if (substr($line, 0, 9) === "deny from") {
                $deniedIPs[] = substr($line, 10);
            }
        }

        return $deniedIPs;
    }

    /**
     * Adds 'deny from $IP' to .htaccess.
     * 
     * @param string $IP
     * @return boolean
     */
    private function __denyIP($IP) {
        $deniedIPs = $this->__getDeniedIPs();
        $deniedIPs[] = $IP;

        $insertion[] = '<Files "*">';
        $insertion[] = 'order allow,deny';
        foreach ($deniedIPs as $deniedIP) {
            $insertion[] = 'deny from ' . $deniedIP;
        }
        $insertion[] = 'allow from all';
        $insertion[] = '</Files>';

        return insert_with_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection', array_unique($insertion));
    }

    /**
     * Removes 'deny from $IP' from .htaccess.
     * 
     * @param string $IP
     * @return boolean
     */
    private function __undenyIP($IP) {
        $deniedIPs = $this->__getDeniedIPs();

        $insertion[] = '<Files "*">';
        $insertion[] = 'order allow,deny';
        foreach ($deniedIPs as $deniedIP) {
            if ($deniedIP !== $IP) {
                $insertion[] = 'deny from ' . $deniedIP;
            }
        }
        $insertion[] = 'allow from all';
        $insertion[] = '</Files>';

        return insert_with_markers($this->__options['htaccess_dir'] . '/.htaccess', 'Brute Force Login Protection', $insertion);
    }

    /**
     * Returns the client ip address.
     * 
     * @return mixed
     */
    private function __getClientIP() {
        $IP = false;

        if ($_SERVER['HTTP_CLIENT_IP']) {
            $IP = $_SERVER['HTTP_CLIENT_IP'];
        } elseif ($_SERVER['HTTP_X_FORWARDED_FOR']) {
            $IP = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif ($_SERVER['HTTP_X_FORWARDED']) {
            $IP = $_SERVER['HTTP_X_FORWARDED'];
        } elseif ($_SERVER['HTTP_FORWARDED_FOR']) {
            $IP = $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif ($_SERVER['HTTP_FORWARDED']) {
            $IP = $_SERVER['HTTP_FORWARDED'];
        } elseif ($_SERVER['REMOTE_ADDR']) {
            $IP = $_SERVER['REMOTE_ADDR'];
        }

        return $IP;
    }

    /**
     * Echoes message with class 'updated'.
     * 
     * @param string $message
     * @return void
     */
    private function __showMessage($message) {
        echo '<div class="updated"><p>' . $message . '</p></div>';
    }

    /**
     * Echoes message with class 'error'.
     * 
     * @param string $message
     * @return void
     */
    private function __showError($message) {
        echo '<div class="error"><p>' . $message . '</p></div>';
    }

}

//Instantiate new instance of BruteForceLoginProtection class
new BruteForceLoginProtection();
