<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Sample extends CI_Controller {

    public function __construct()
    {
        parent::__construct();

        $this->load->helper('url');

        // Load Azure AD Single Sign-on library
        $this->load->library('aad_auth');
    }

    public function index()
    {
        $this->load->view('sample/index');
    }

    /**
     * This illustrates simple logging in.
     */
    public function login()
    {
        $return_to = $this->input->get('return_to');
        $this->aad_auth->login($return_to === NULL ? site_url() : $return_to);
    }

    /**
     * This illustrates an entirely unprotected page.
     */
    public function unprotected_page()
    {
        $this->load->view('sample/unprotected_page');
    }

    /**
     * This illustrates showing different views to protect an entire page.
     **/
    public function protected_page()
    {
        if (!$this->aad_auth->is_logged_in())
        {
            $this->aad_auth->login();
        }
        else
        {
            $data = array(
                'user_info' => $this->aad_auth->user_info(),
            );
            $this->load->view('sample/protected_page', $data);
        }
    }

    /**
     * This illustrates providing the sign-in state to the view, to allow
     * for some display logic in the view itself.
     */
    public function partially_protected_page()
    {
        $data = array(
            'is_logged_in' => $this->aad_auth->is_logged_in(),
            'login_url' => site_url('sample/login?return_to=' . urlencode(current_url())),
            'logout_url' => site_url('sample/logout?return_to=' . urlencode(current_url())),
        );

        $this->load->view('sample/partially_protected_page', $data);
    }

    /**
     * A simple authentication response handler.
     *
     * TODO: Move all validation logic to the library, allow library user to set error and success handler.
     */
    public function handle_response()
    {
        $this->load->library('session');

        $state = $this->input->get('state');
        $error = $this->input->get('error');
        $code = $this->input->get('code');

        // Regardless if authentication was successful or not, the state value MUST be the expected one.
        if ($this->session->aad_auth_nonce === NULL || $this->session->aad_auth_nonce !== $state)
        {
            die('State value returned (\'' . $state . '\') is not the value expected (\''
                 . $this->session->aad_auth_nonce . '\').');
        }
        else
        {
            if ($error !== NULL || $code === NULL)
            {
                // Error during authentication
                echo '<pre>' . $error . '</pre>';
                echo '<pre>' . $this->input->get('error_description') . '</pre>';
            }
            else
            {
                // Successful authentication, now use the authentication code to get an Access Token and ID Token
                echo '<pre>'; var_dump($this->input->get()); echo '</pre>';
                $this->aad_auth->request_tokens($this->input->get('code'));
            }
        }
    }

    /**
     * This illustrates signing out (of both this site and Azure AD).
     */
    public function logout()
    {
        $return_to = $this->input->get('return_to');
        $this->aad_auth->logout($return_to === NULL ? site_url() : $return_to);
    }


    /**
     * This illustrates logging out of the site (but not of Azure AD), useful for testing.
     */
    public function revoke_session()
    {
        $return_to = $this->input->get('return_to');
        $this->aad_auth->revoke_session();
        redirect($return_to === NULL ? site_url() : $return_to);
    }
}
