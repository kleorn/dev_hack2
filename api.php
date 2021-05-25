<?php
include "settings.php"; //passwords and other confidential info, do not share!
class API{
	static $response=Array();
	static $lang="en";
	static $pdo;
	static $errorBase=Array(
        "noAuthToken"=>Array(
            "ru"=>"Отсутствует токен авторизации в хедере AuthToken.",
            "en"=>"No authorization token in AuthToken header."
        ),
        "wrongAuthToken"=>Array(
            "ru"=>"Неправильный токен авторизации.",
            "en"=>"Wrong authorization token."
        ),
	    "noName"=>Array(
	        "ru"=>"Отсутствует имя пользователя.",
            "en"=>"No user name."
        ),
        "noID"=>Array(
            "ru"=>"Отсутствует ID пользователя.",
            "en"=>"No user ID."
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
        "registerError"=>Array(
            "ru"=>"Не удалось зарегистрировать пользователя: данный логин уже занят.",
            "en"=>"Could not register user: provided login is busy."
        ),
        "sqlError"=>Array(
            "ru"=>"Ошибка выполнения SQL-запроса.",
            "en"=>"SQL query execution error."
        ),
        "authError"=>Array(
            "ru"=>"Ошибка авторизации: неверные логин/пароль пользователя.",
            "en"=>"Authorization error: wrong user login/password."
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

        //если есть ошибки - отправляем и выходим
        if (isset(API::$response["errors"])){
            API::sendResponse();
            die();
        }

        API::connectDB();
        $registrationDate = new DateTime("now");
        $registrationDateText = $registrationDate->format("Y-m-d H:i:s");
        $query="INSERT INTO users (name, login, pwd_hash, language,registration_date) VALUES(\"".$requestArr["name"]."\",\"".$requestArr["login"]."\",\"".md5($requestArr["password"])."\",\"".$requestArr["language"]."\",\"".$registrationDateText."\")";
        $modifiedStringsCount=API::$pdo->exec($query);
        if ($modifiedStringsCount<>1){
            self::addError("registerError");
        }
        else {


            API::$response["result"]=API::$pdo->lastInsertId();
        }
        self::sendResponse();
    }

    //добавление ошибки в список ошибок для отправки
    static function addError($error){
	    $curr_message = API::$errorBase[$error][API::$lang];
	    API::$response["errors"][]=Array("code" => $error, "message" =>$curr_message);
    }

    public static function auth(){
        $requestBody = file_get_contents('php://input');
        //echo $requestBody;
        $requestArr=json_decode($requestBody,true);
//        print_r($requestArr);
        if (!isset($requestArr)) {
            API::addError("wrongJSON");
        }
        if (!isset($requestArr["login"])) {
            API::addError("noLogin");
        }
        if (!isset($requestArr["password"])) {
            API::addError("noPassword");
        }
        if (!isset($requestArr["language"])) {
            $requestArr["language"]="eu-US"; //английский язык по умолчанию
        }

        //если есть ошибки - отправляем и выходим
        if (isset(API::$response["errors"])){
            API::sendResponse();
            die();
        }

        API::connectDB();
        $query="SELECT id, name, registration_date FROM users WHERE login=\"".$requestArr["login"]."\" AND pwd_hash=\"".md5($requestArr["password"])."\"";
        $pdoStatement=API::$pdo->query($query);
        if ($pdoStatement==false){
            self::addError("sqlError");
            self::sendResponse();
            die();
        }
        $result=$pdoStatement->fetch(PDO::FETCH_ASSOC);
        $user_id=$result["id"];

        if (!isset($result["id"])){
            header(" ",true,403);
            self::addError("authError");
            self::sendResponse();
            die();
        }

        //генерируем bearer-токен авторизации 64 байта в hex - 128 символов
        //срок действия токена не ограничиаем за ненадобностью
        $token = bin2hex(random_bytes(64));
        //echo $token;
        $query="REPLACE INTO tokens (user_id, token) VALUES(\"".$user_id."\",\"".$token."\")";
        $modifiedStringsCount=API::$pdo->exec($query);
        if ($modifiedStringsCount==0){
            self::addError("sqlError");
        }

        header("AuthToken:".$token,true,200);

        //генерируем тело ответа
        API::$response["result"]["user"]["id"]=$result["id"];
        API::$response["result"]["user"]["name"]=$result["name"];
        API::$response["result"]["user"]["date_registration"]=$result["registration_date"];
        self::sendResponse();
    }

    public static function updateUser(){
	    //поскольку не указано обратное, считаем, что любой авторизованный пользователь может выполнить update
        $requestBody = file_get_contents('php://input');
        $requestArr=json_decode($requestBody,true);
        $requestHeaders=getallheaders();
        if (!isset($requestArr)) {
            API::addError("wrongJSON");
        }
        if (!isset($requestArr["id"])) {
            API::addError("noID");
        }
        if (!isset($requestArr["name"])) {
            API::addError("noName");
        }
        if (!isset($requestArr["language"])) {
            $requestArr["language"]="eu-US"; //английский язык по умолчанию, не выдаем ошибку
        }
        if (!isset($requestHeaders["AuthToken"])) {
            API::addError("noAuthToken");
        }

        //если есть ошибки - отправляем и выходим
        if (isset(API::$response["errors"])){
            API::sendResponse();
            die();
        }

        API::connectDB();
        $query="SELECT user_id FROM tokens WHERE token=\"".$requestHeaders["AuthToken"]."\"";
        $pdoStatement=API::$pdo->query($query);
        if ($pdoStatement==false){
            self::addError("sqlError");
            self::sendResponse();
            die();
        }
        $result=$pdoStatement->fetch(PDO::FETCH_ASSOC);

        if (!isset($result["user_id"])){
            header(" ",true,403);
            self::addError("wrongAuthToken");
            self::sendResponse();
            die();
        }
        $currentUserId=$result["user_id"];

        $query="UPDATE users SET name=\"".$requestArr["name"]."\", language=\"".$requestArr["language"]."\" WHERE id=\"".$requestArr["id"]."\"";
        $modifiedStringsCount=API::$pdo->exec($query);
        if ($modifiedStringsCount==0){
            self::addError("sqlError");
        }

        self::sendResponse();
    }


    static function sendResponse(){
        $response_json=json_encode(API::$response,JSON_UNESCAPED_UNICODE);//ненавижу unicode escape
        echo $response_json;
    }
    static function connectDB(){
        API::$pdo = new PDO('mysql:host='.mysqlServer.';dbname='.mysqlDB.";charset=utf8;", mysqlUser, mysqlPass);
    }
}