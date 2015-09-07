<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/* ----------------------------------------------------------- */
/*    AZURE ACTIVE DIRECTORY SINGLE SIGN-ON FOR CODEIGNITER    */
/* ----------------------------------------------------------- */

/**
 * The identifier Guid or domain name for the directory this application was registered in.
 *
 * Along with the 'authority' config (below), this is used to construct the authorization, token and logout endpoints.
 *
 * E.g. $config['directory_identifier'] = '2916ea73-ecdf-4ed4-94ad-4a30a6e7a3c3';
 * E.g. $config['directory_identifier'] = 'contoso.com';
 */
$config['directory_identifier'] = '<your directory identifier or domain name>';

/**
 * The client ID of the application (as registered in Azure AD).
 *
 * E.g. $config['client_id'] = '2916ea73-ecdf-4ed4-94ad-4a30a6e7a3c3';
 */
$config['client_id'] = '<paste your client ID here>';


/**
 * The secret key for the application (as registered in Azure AD).
 *
 * E.g. $config['client_secret'] = '9ltvIfj9zVISfYyR5oEdmBmbnDBsEPDAZpJeURgpidEj';
 */
$config['client_secret'] = '<paste your secret key here>';

/**
 * The segment of this application that will be used as the redirect URI.
 *
 * This will be used as the parameter to site_url().
 * E.g. $config['redirect_uri_segment'] = 'sample/handle_response';
 */
$config['redirect_uri_segment'] = '<URI segment to the response handler>';



/* ----------------------------------------------------------- */
/*   (You typically will not need to change anything else.)    */
/* ----------------------------------------------------------- */

/**
 * The root of the Azure Active Directory endpoints
 */
$config['authority'] = 'https://login.microsoftonline.com';

/**
 * The resource for which we will be asking for an access token.
 */
$config['resource_uri'] = 'https://graph.windows.net';
