<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Aad_auth {

    private $_ci;

    public function __construct()
    {
        $this->_ci =& get_instance();
    }

    /**
     * Indicates if the current user is signed in ro Azure AD or not.
     */
    public function is_logged_in()
    {
        return FALSE;
    }

    /**
     * Redirects the user to Azure AD to sign in.
     *
     * After authentication, will redirect the user to $return_to, or will do a best
     * guess at where they were.
     **/
    public function login($return_to = NULL)
    {
        if ($return_to === NULL)
        {
            // TODO: Include query parameters
            $return_to = $this->_ci->router->fetch_class() . '/' . $this->_ci->router->fetch_method();
        }

        $this->_get_authorization_url();
    }

    private function _get_authorization_url()
    {
        $antiforgery_id = $this->_generate_guid();
        $auth_url = '';
        return $auth_url;
    }

    private function _generate_guid()
    {
        if (!function_exists('com_create_guid')) {
            function com_create_guid() {
                $data = openssl_random_pseudo_bytes(16);
                $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
                $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
                return vsprintf('{%s%s-%s-%s-%s-%s%s%s}', str_split(bin2hex($data), 4));
            }
        }
        return strtolower(trim(com_create_guid(), '{}'));
    }
}