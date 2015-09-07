<html>
    <head>
        <style>
            body { margin: 10px; font-family: sans-serif;}
        </style>
    </head>
    <body>
        <h1>Azure Active Directory Single Sign-on for CodeIgniter Demo</h1>
        <p>This is an protected page. Only people who have signed in can see it.</p>
        <p>You are signed in as <?= print_r($user_info, TRUE) ?>.</p>
        <?php include ('footer.php'); ?>
    </body>
</html>