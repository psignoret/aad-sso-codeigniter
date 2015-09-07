[![Stories in Ready](https://badge.waffle.io/psignoret/aad-sso-codeigniter.png?label=ready&title=Ready)](https://waffle.io/psignoret/aad-sso-codeigniter)
# aad-sso-codeigniter
Authentication for a CodeIgniter site using Azure Active Directory

**IMPORTANT**: This does not yet validate tokens and MUST NOT be used.

Use Azure Active Directory to secure access to a site or application that is based on the CodeIgniter PHP framework.

This includes:
 * The Azure Active Directory for CodeIgniter library.
 * A (very) basic sample showing how the Azure AD library can be used to secure access to entire pages (i.e. controller methods), or portions of a page.

Notes:

 * This library uses CodeIgniter's [Sessions Library](http://www.codeigniter.com/user_guide/libraries/sessions.html). This means the library must be configured for use. (E.g. if using the [files driver](http://www.codeigniter.com/user_guide/libraries/sessions.html#files-driver), the directory must be set.)


*IMPORTANT: This is a work in progress. You should not use this yet for any production sites or sensitive information.*