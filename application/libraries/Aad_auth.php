<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Aad_auth {

    protected $CI;

    public $settings;

    function __construct()
    {
        $this->CI =& get_instance();
        $this->CI->load->library('session');

        $this->_load_settings();
    }

    /**
     * Indicates if the current user is signed in to this application with Azure AD or not.
     */
    public function is_logged_in()
    {
        return isset($_SESSION['aad_auth_is_logged_in']) && $_SESSION['aad_auth_is_logged_in'];
    }

    /**
     * Redirects the user to Azure AD to sign in (the OpenID Connect Authentication Request).
     *
     * After authentication, will redirect the user to $return_to, or will do a best
     * guess at where they were.
     *
     * @param string    $return_to  The URL where the user will be returned to after signing in.
     */
    public function login($return_to = NULL)
    {
        $return_to = $return_to === NULL ? $this->_get_current_page() : $return_to;

        $this->CI->load->helper('url');
        redirect($this->get_login_url($return_to));
    }


    public function get_login_url($return_to = NULL)
    {
        $return_to = $return_to === NULL ? $this->_get_current_page() : $return_to;
        return $this->_get_authorization_url($return_to);
    }

    /**
     * End the current session and redirects the user to the Azure AD logout URL.
     *
     * After logging out, will redirect the user to $return_to, or to the best guess at where they were.
     *
     * @param string    $return_to  The URL where the user will be returned to after signing out.
     */
    public function logout($return_to = NULL)
    {
        $return_to = $return_to === NULL ? $this->_get_current_page() : $return_to;

        $this->revoke_session();

        $this->CI->load->helper('url');
        redirect($this->get_logout_url($return_to));
    }

    public function get_logout_url($return_to = NULL)
    {
        $return_to = $return_to === NULL ? $this->_get_current_page() : $return_to;
        return $this->settings['logout_endpoint'] . '?post_logout_redirect_uri=' . urlencode($return_to);
    }


    /**
     * Marks the current session as signed out and clears the session values.
     */
    public function revoke_session()
    {
        $_SESSION['aad_auth_is_logged_in'] = FALSE;
        unset($_SESSION['aad_auth_result']);
    }

     /**
     * Uses an authorization code from a successful authentication response and retrieves an access token, ID token and refresh token.
     *
     * @param string    $code                       The authorization code from a successful and validated authentication response.
     * @param string    $response_handler_success   The handler to use for a successful token response.
     * @param string    $response_handler_error     The handler to use for error token response.
     */
    public function request_tokens($code, $response_handler_success = NULL, $response_handler_error = NULL)
    {
        $token_request = http_build_query(
            array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->settings['redirect_uri'],
                'client_id' => $this->settings['client_id'],
                'client_secret' => $this->settings['client_secret'],
                'resource' => $this->settings['resource_uri'],
            )
        );

        // Build the stream context options for the HTTPS request
        $options = array(
            'http' => array(
                'method'  => 'POST',
                'header'  => 'Content-type: application/x-www-form-urlencoded',
                'content' => $token_request,
                'ignore_errors' => TRUE,    // We want to actually receive all the error codes
                'verify_peer' => TRUE,      // This is default in PHP 5.6, but not before.
            )
        );

        // Open the stream and make the request
        $token_endpoint = $this->settings['token_endpoint'];
        $context = stream_context_create($options);
        $fp = @fopen($token_endpoint, 'rb', FALSE, $context);
        if (!$fp)
        {
            throw new Exception('Error encountered when opening ' . $token_endpoint);
        }

        // Get and decode the response from the authorization server
        $response = @stream_get_contents($fp);
        if ($response === FALSE)
        {
            throw new Exception('Error reading from ' . $token_endpoint);
        }
        $response = json_decode($response, TRUE);

        // A successful response will have 'access_token' and 'token_type' defined. An error
        // response will have 'error' defined. Anything else is unexpected.
        if (isset($response['access_token']) && isset($response['token_type']))
        {
            $this->_handle_token_response_success($response, $response_handler_success);
        }
        else
        {
            if (isset($response['error']))
            {
                $this->_handle_token_response_error($response, $response_handler_error);
            }
            else
            {
                throw new Exception('Unexpected response to token request.');
            }
        }
    }

    /**
     * Returns basic user profile details from the ID Token if user is signed in, NULL otherwise.
     */
    public function user_info()
    {
        if ($this->is_logged_in())
        {
            return $_SESSION['aad_auth_result']['user_info'];
        }
        return NULL;
    }

    /**
     * Handles an successful response to an access token request.
     *
     * The default handler will mark the session as logged in, place the Access Token and
     * ID Token in the session, and redirect the user-agent to the return_to URL.
     */
    private function _handle_token_response_success($response, $response_handler = NULL)
    {
        if ($response_handler === NULL)
        {
            // TODO: Validate ID Token

            // TODO: Populate user_info from ID Token
            $user_info = $response['id_token'];

            $_SESSION['aad_auth_result'] = array(
                'token_type'    => $response['token_type'],
                'access_token'  => $response['access_token'],
                'id_token'      => $response['id_token'],
                'refresh_token' => isset($response['refresh_token']) ? $response['refresh_token'] : NULL,
                'user_info'     => $user_info,
            );

            // Mark user as logged in
            $_SESSION['aad_auth_is_logged_in'] = TRUE;

            // Redirect back to original page
            $this->CI->load->helper('url');
            redirect($_SESSION['aad_auth_return_to']);
        }
        else
        {
            throw new Exception('Not implemented: Custom response handlers');
        }
    }

    /**
     * Handles a successful response to an access token request.
     *
     * The default handler will terminate with an error.
     */
    private function _handle_token_response_error($response, $response_handler = NULL)
    {
        if ($response_handler === NULL)
        {
            $_SESSION['aad_auth_is_logged_in'] = FALSE;
            die('Error getting access token. ' . print_r($response, TRUE));
        }
        else
        {
            throw new Exception('Not implemented: Custom response handlers');
        }
    }

    /**
     * Returns the OpenID Connect authentication request URL.
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest    OpenID Connect 1.0 Authentication Request
     *
     * @param string    $antiforgery_id The value used as state and nonce for the request.
     */
    private function _get_authorization_url($return_to)
    {
        $antiforgery_id = $this->_new_guid();

        // Save the nonce and return_to values to flash data
        $_SESSION['aad_auth_nonce'] = $antiforgery_id;
        $_SESSION['aad_auth_return_to'] = $return_to;
        $this->CI->session->mark_as_flash(array('aad_auth_nonce', 'aad_auth_return_to'));

        $auth_url = $this->settings['authorization_endpoint'] . '?' .
            http_build_query(
                array(
                    'scope' => 'openid',
                    'response_type' => 'code',
                    'client_id' => $this->settings['client_id'],
                    'redirect_uri' => $this->settings['redirect_uri'],
                    'state' => $antiforgery_id,
                    'nonce' => $antiforgery_id,
                    'domain_hint' => $this->settings['org_domain_hint'],
                    'resource' => $this->settings['resource_uri'],
                )
            );

        return $auth_url;
    }

    /**
     * Returns a best guess at the current location.
     */
    private function _get_current_page()
    {
        $this->CI->load->helper('url');
        return current_url();
        //return $this->CI->router->fetch_class() . '/' . $this->CI->router->fetch_method();
    }

    /**
     * Loads the settings from the config.
     */
    private function _load_settings()
    {
        // Load the library's config (into a section, to avoid collisions)
        $this->CI->config->load('aad_auth', TRUE);
        $c =& $this->CI->config->config['aad_auth'];

        // Set the final configuration values
        $this->settings = array(
            'authorization_endpoint'    => $c['authority'] . '/' . $c['directory_identifier'] . '/oauth2/authorize',
            'token_endpoint'            => $c['authority'] . '/' . $c['directory_identifier'] . '/oauth2/token',
            'logout_endpoint'           => $c['authority'] . '/' . $c['directory_identifier'] . '/oauth2/logout',
            'client_id'                 => $c['client_id'],
            'client_secret'             => $c['client_secret'],
            'resource_uri'              => $c['resource_uri'],
            'redirect_uri'              => $this->CI->config->site_url($c['redirect_uri_segment']),
        );
    }

    /**
     * Returns a cryptographically random globally unique identifier.
     */
    private function _new_guid()
    {
        $data = openssl_random_pseudo_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}