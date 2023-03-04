<?php
    $attach ="mysql:host=mysql;dbname=database;charset=utf8";
    $username = "mysql";
    $password = "mysql";

    try{
        $db = new PDO($attach,$username,$password);
    } catch(PDOException $e){
        $message = $e->getMessage();
        print($message);
        return 0;
    }

    $sql = "CREATE TABLE texts (user_id int auto_increment PRIMARY KEY,title text,content text,create_time datetime)";
    $output = $db->query($sql);
    $sql = "INSERT INTO texts (title,content,create_time) VALUES
    ('first','first content',NOW()),
    ('second','second content',NOW()),
    ('third','third content',NOW())";
    $output = $db->query($sql);
    $sql = "SELECT * FROM texts";
    $output = $db->query($sql);
    return 0;

?>