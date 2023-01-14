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

    print("success");
    $sql = "CREATE TABLE texts (id int,name text)";
    $output = $db->query($sql);
    $sql = "INSERT INTO texts (id,name) VALUES(1,'first test')";
    $output = $db->query($sql);

    return 0;

?>