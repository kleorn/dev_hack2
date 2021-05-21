<?php
class API{
	static $mysqlServer="localhost";
	static $mysqlPort=3306;
	static $errors=Array();
	static $lang="ru";
	static $errorBase=Array(
	    "noName"=>Array(
	        "ru"=>"Отсутствует имя пользователя.",
            "en"=>"No user name."
        )
    );


	public static function registerUser(){
	$requestBody = file_get_contents('php://input');
	//print_r($requestBody);
        echo $requestBody;
        $requestArr=json_decode($requestBody,true);
        print_r($requestArr);

        if (!isset($requestArr["name"])) {
            API::addError("noName");
        }
    }

    //добавление ошибки в список ошибок для отправки
    static function addError($error){
	    echo API::$errorBase[$error][API::$lang];
    }
}