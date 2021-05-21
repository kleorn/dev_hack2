<?php
class API{
	static $mysqlServer="localhost";
	static $mysqlPort=3306;
	static $response=Array();
	static $lang="en";
	static $errorBase=Array(
	    "noName"=>Array(
	        "ru"=>"Отсутствует имя пользователя.",
            "en"=>"No user name."
        ),
        "noPassword"=>Array(
            "ru"=>"Отсутствует пароль пользователя.",
            "en"=>"No user password."
        ),
        "noLanguage"=>Array(
            "ru"=>"Отсутствует язык пользователя.",
            "en"=>"No user language."
        ),
        "noLogin"=>Array(
            "ru"=>"Отсутствует логин пользователя.",
            "en"=>"No user login."
        ),
        "wrongJSON"=>Array(
            "ru"=>"Неверный формат JSON в теле запроса.",
            "en"=>"Wrong JSON structure in the request body."
        ),
    );


	public static function registerUser(){
	$requestBody = file_get_contents('php://input');
        //echo $requestBody;
        $requestArr=json_decode($requestBody,true);
//        print_r($requestArr);
        if (!isset($requestArr)) {
            API::addError("wrongJSON");
        }
        if (!isset($requestArr["name"])) {
            API::addError("noName");
        }
        if (!isset($requestArr["password"])) {
            API::addError("noPassword");
        }
        if (!isset($requestArr["language"])) {
            API::addError("noLanguage");
        }
        if (!isset($requestArr["login"])) {
            API::addError("noLogin");
        }


        self::sendResponse();
    }

    //добавление ошибки в список ошибок для отправки
    static function addError($error){
	    $curr_message = API::$errorBase[$error][API::$lang];
	    API::$response["errors"][]=Array("code" => $error, "message" =>$curr_message);
    }

    static function sendResponse(){
        $response_json=json_encode(API::$response);
        echo $response_json;
    }
}