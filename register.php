<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Connect to the database
    $servername = "localhost";
    $username = "username";
    $password_db = "password";
    $dbname = "myDB";

    $conn = new mysqli($servername, $username, $password_db, $dbname);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 

    // Prepare and execute the query to insert the new user into the database
    $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $email, $hashed_password);
    $stmt->execute();
    $stmt->close();

    // Confirm registration
    echo 'Cadastro realizado com sucesso!';
    $conn->close();
}

