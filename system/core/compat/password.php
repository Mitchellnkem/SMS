php
Copy code
<?php

defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * PHP ext/standard/password compatibility package
 *
 * @package     CodeIgniter
 * @subpackage  CodeIgniter
 * @category    Compatibility
 * @author      Andrey Andreev
 * @link        http://codeigniter.com/user_guide/
 * @link        http://php.net/password
 */

// ------------------------------------------------------------------------

if (!function_exists('is_php')) {
    function is_php($version)
    {
        static $_is_php;
        $version = (string) $version;

        if (!isset($_is_php[$version])) {
            $_is_php[$version] = version_compare(PHP_VERSION, $version, '>=');
        }

        return $_is_php[$version];
    }
}

// ------------------------------------------------------------------------

if (!is_php('5.3.7') || defined('HHVM_VERSION')) {
    return;
}

// ------------------------------------------------------------------------

if (!defined('CRYPT_BLOWFISH') || CRYPT_BLOWFISH !== 1) {
    return;
}

// ------------------------------------------------------------------------

defined('PASSWORD_BCRYPT') || define('PASSWORD_BCRYPT', 1);
defined('PASSWORD_DEFAULT') || define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);

// ------------------------------------------------------------------------

if (!function_exists('password_get_info')) {
    /**
     * password_get_info()
     *
     * @link    http://php.net/password_get_info
     * @param   string  $hash
     * @return  array
     */
    function password_get_info($hash)
    {
        return (strlen($hash) < 60 || sscanf($hash, '$2y$%d', $hash) !== 1)
            ? array('algo' => 0, 'algoName' => 'unknown', 'options' => array())
            : array('algo' => 1, 'algoName' => 'bcrypt', 'options' => array('cost' => $hash));
    }
}

// ------------------------------------------------------------------------

if (!function_exists('password_hash')) {
    /**
     * password_hash()
     *
     * @link    http://php.net/password_hash
     * @param   string  $password
     * @param   int     $algo
     * @param   array   $options
     * @return  mixed
     */
    function password_hash($password, $algo, array $options = array())
    {
        $func_override = extension_loaded('mbstring') && ini_get('mbstring.func_override');

        if ($algo !== 1) {
            trigger_error('password_hash(): Unknown hashing algorithm: ' . (int) $algo, E_USER_WARNING);
            return null;
        }

        if (isset($options['cost']) && ($options['cost'] < 4 || $options['cost'] > 31)) {
            trigger_error('password_hash(): Invalid bcrypt cost parameter specified: ' . (int) $options['cost'], E_USER_WARNING);
            return null;
        }

        if (isset($options['salt']) && strlen($options['salt']) < 22) {
            trigger_error('password_hash(): Provided salt is too short: ' . strlen($options['salt']) . ' expecting 22', E_USER_WARNING);
            return null;
        } elseif (!isset($options['salt'])) {
            $options['salt'] = '';

            if (function_exists('random_bytes')) {
                try {
                    $options['salt'] = random_bytes(16);
                } catch (Exception $e) {
                    // Handle error if random_bytes() fails
                    log_message('error', 'compat/password: Unable to generate random bytes using random_bytes().');
                    return false;
                }
            } elseif (function_exists('openssl_random_pseudo_bytes')) {
                $options['salt'] = openssl_random_pseudo_bytes(16, $crypto_strong);
                if (!$crypto_strong) {
                    // Handle error if openssl_random_pseudo_bytes() fails to provide strong randomness
                    log_message('error', 'compat/password: openssl_random_pseudo_bytes() did not return a strong result.');
                    return false;
                }
            } else {
                // Handle error if no suitable CSPRNG is found
                log_message('error', 'compat/password: No CSPRNG available.');
                return false;
            }

            $options['salt'] = str_replace('+', '.', rtrim(base64_encode($options['salt']), '='));
        } elseif (!preg_match('#^[a-zA-Z0-9./]+$#D', $options['salt'])) {
            $options['salt'] = str_replace('+', '.', rtrim(base64_encode($options['salt']), '='));
        }

        $options['cost'] = isset($options['cost']) ? (int) $options['cost'] : 10;

        return (strlen($password = crypt($password, sprintf('$2y$%02d$%s', $options['cost'], $options['salt']))) === 60)
            ? $password
            : false;
    }
}

// ------------------------------------------------------------------------

if (!function_exists('password_needs_rehash')) {
    /**
     * password_needs_rehash()
     *
     * @link    http://php.net/password_needs_rehash
     * @param   string  $hash
     * @param   int     $algo
     * @param   array   $options
     * @return  bool
     */
    function password_needs_rehash($hash, $algo, array $options = array())
    {
        $info = password_get_info($hash);

        if ($algo !== $info['algo']) {
            return true;
        } elseif ($algo === 1) {
            $options['cost'] = isset($options['cost']) ? (int) $options['cost'] : 10;
            return ($info['options']['cost'] !== $options['cost']);
        }

        return false;
    }
}

// ------------------------------------------------------------------------

if (!function_exists('password_verify')) {
    /**
     * password_verify()
     *
     * @link    http://php.net/password_verify
     * @param   string  $password
     * @param   string  $hash
     * @return  bool
     */
    function password_verify($password, $hash)
    {
        if (strlen($hash) !== 60 || strlen($password = crypt($password, $hash)) !== 60) {
            return false;
        }

        $compare = 0;
        for ($i = 0; $i < 60; $i++) {
            $compare |= (ord($password[$i]) ^ ord($hash[$i]));
        }

        return ($compare === 0);
    }
}