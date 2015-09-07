        <p>
            Try going to a <?= anchor('sample/protected_page', 'protected page') ?>,
            an <?= anchor('sample/unprotected_page', 'unprotected page') ?>, or to a
            <?= anchor('sample/partially_protected_page', 'partially protected page') ?>.
        </p>
        <p>
            You can <?= anchor('sample/login', 'sign in') ?> or <?= anchor('sample/logout', 'sign out') ?>, or you
            find it useful to <?= anchor('sample/revoke_session', 'log out of this site') ?> (but not of Azure AD).
        </p>