<?php
class API{
	static $mysqlServer="localhost";
	static $mysqlPort=3306;
	public static function registerUser(){
	$requestBody = file_get_contents('php://input');
	//print_r($requestBody);
        echo $requestBody;
	echo "User registered?! ".self::$mysqlPort;
	}
}//NOW1