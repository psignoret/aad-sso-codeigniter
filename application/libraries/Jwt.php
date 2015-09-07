<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * A CodeIgniter library that wraps \Firebase\JWT\JWT methods.
 */
class Jwt {

    function __construct()
    {
        // TODO: Is this the best way to do this? (Issue #4 at psignoret/aad-sso-codeigniter.)
        require_once(APPPATH . 'libraries/JWT/JWT.php');
        require_once(APPPATH . 'libraries/JWT/BeforeValidException.php');
        require_once(APPPATH . 'libraries/JWT/ExpiredException.php');
        require_once(APPPATH . 'libraries/JWT/SignatureInvalidException.php');
    }

    /**
     * Wrapper function for JWT::decode.
     */
    public function decode($jwt, $key, $allowed_algs = array())
    {
        return \Firebase\JWT\JWT::decode($jwt, $key, $allowed_algs);
    }
}
