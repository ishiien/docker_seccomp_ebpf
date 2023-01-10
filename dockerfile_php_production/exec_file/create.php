<?php
    $attach ="mysql:host=mysql_test;dbname=database;charset=utf8";
    $username = "mysql";
    $password = "mysql";

    try{
        $db = new PDO($attach,$username,$password);
        print("sucess");
    } catch(PDOException $e){
        $message = $e->getMessage();
        print($message);
    }

    $sql = $db->prepare('create table texts (id int,comment text)');
    $sql->execute();

?>