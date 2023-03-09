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
    $sql = "SELECT * FROM texts";
    $output = $db->query($sql);
    $sql = "DROP TABLE texts";
    $output = $db->query($sql);

?>