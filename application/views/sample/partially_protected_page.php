<html>
    <head>
        <style>
            body { margin: 10px; font-family: sans-serif;}
        </style>
    </head>
    <body>
        <h1>Azure Active Directory Single Sign-on for CodeIgniter Demo</h1>
        <p>
            This is an partially protected page. Everyone can get to the page and see this paragraph, but some of the
            content is only available if the user is signed in.
        </p>
        <?php if ($is_logged_in) : ?>
        <p style="background-color: #eeffee; padding: 10px;">
            This is restricted content and only signed in users can see it. You can <?= anchor($logout_url, 'sign out') ?>
            and come straight back here.
        </p>
        <?php else : ?>
        <p style="background-color: #ffeeee; padding: 10px;">
            You are not signed in, so you can't see the restricted content. You can <?= anchor($login_url, 'sign in') ?>
            and come straight back.
        <p>
        <?php endif; ?>
        <?php include ('footer.php'); ?>
    </body>
</html>