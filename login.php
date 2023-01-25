<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Connect to the database
    $servername = "localhost";
    $username = "username";
    $password_db = "password";
    $dbname = "myDB";

    $conn = new mysqli($servername, $username, $password_db, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 

    // Prepare and execute the query to get the user from the database
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // User found
        $row = $result->fetch_assoc();
        $hashed_password = $row['password'];

        // Verify the password
        if (password_verify($password, $hashed_password)) {
            // Password is correct, start a new session and save the user ID
            session_start();
            $_SESSION['user_id'] = $row['id'];

            // Redirect to the protected page
            header('Location: protegida.php');
            exit;
        } else {
            echo 'Email ou senha incorretos.';
        }
    } else {
        echo 'Email ou senha incorretos.';
    }
    $stmt->close();
    $conn->close();
}

