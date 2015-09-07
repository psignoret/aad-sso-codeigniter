<html>
    <head>
        <style>
            body { margin: 10px; font-family: sans-serif;}
        </style>
    </head>
    <body>
        <h1>Azure Active Directory Single Sign-on for CodeIgniter Demo</h1>
        <p>This is a protected page. Only people who have signed in can see it.</p>
        <p>
            You are signed in as <strong><?= $user_info['displayable_id'] ?></strong>, and this is your <code>id_token</code>:
            <pre style="background-color: #eeeeee; padding: 10px;"><?= print_r($id_token, TRUE) ?></pre>
        </p>
        <?php include ('footer.php'); ?>
    </body>
</html>