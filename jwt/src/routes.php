<?php

use Slim\Http\Request;
use Slim\Http\Response;
use Respect\Validation\Validator as v;
use Firebase\JWT\JWT;


class Auth
{
    private static $secret_key = 'Sdw1s9x8@';
    private static $encrypt = ['HS256'];
    private static $aud = null;
    
    public static function SignIn($data)
    {
        $time = time();
        
        $token = array(
            'exp' => $time + (60*10),
            'aud' => self::Aud(),
            'data' => $data
        );

        return JWT::encode($token, self::$secret_key);
    }
    
    public static function Check($token)
    {
        if(empty($token))
        {
            throw new Exception("Invalid token supplied.");
        }
        
        $decode = JWT::decode(
            $token,
            self::$secret_key,
            self::$encrypt
        );
        
        if($decode->aud !== self::Aud())
        {
            throw new Exception("Invalid user logged in.");
        }
    }
    
    public static function GetData($token)
    {
        return JWT::decode(
            $token,
            self::$secret_key,
            self::$encrypt
        )->data;
    }
    
    private static function Aud()
    {
        $aud = '';
        
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $aud = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $aud = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $aud = $_SERVER['REMOTE_ADDR'];
        }
        
        $aud .= @$_SERVER['HTTP_USER_AGENT'];
        $aud .= gethostname();
        
        return sha1($aud);
    }
}







$app->post('/permission/', function (Request $request, Response $response, array $args) {
    try {
    $params=  $request->getParsedBody();
     if(!v::numeric()->validate($params["dni"]) || !v::alnum()->noWhitespace()->validate($params["hash"]) || !v::numeric()->validate($params["idRol"])){
         throw new Exception();
     }
     $dni=$params["dni"];
    $hash=$params["hash"];
    $idrol=$params["idRol"];
    $response->getBody()->write(Auth::SignIn([
        'dni' =>$dni,
        'hash' =>$hash,
        'idRol'=>$idrol
    ]) 
 );
 return $response;
    } catch (Exception $exc) {
	return $response->withStatus(400)
            ->withHeader('Content-Type', 'text/html')
            ->write('NULL');
    }


});

$app->post('/validate/', function (Request $request, Response $response, array $args) {
 try {
 $token=(string)$request->getHeader('token')[0];
  if(!v::stringType()->notEmpty()->validate($token)){
         throw new Exception();
     }
 $response->getBody()->write(json_encode(Auth::GetData($token))
);
     
 } catch (Exception $exc) {
     return $response->withStatus(400)
            ->withHeader('Content-Type', 'text/html')
            ->write('NULL');
     
 }


 return $response;
});


$app->post('/timeForV/', function (Request $request, Response $response, array $args) {
 try {

$token=(string)$request->getHeader('token')[0];
  if(!v::stringType()->notEmpty()->validate($token)){
         throw new Exception("Token Expirado");
  }
$miToken=json_encode(Auth::GetData($token));
if(is_null(json_decode($miToken))["dni"])throw new Exception("Token invalido");
 

    $params=  $request->getParsedBody();
     if(!v::alnum("/")->validate($params["date"]) || !v::alnum(":")->noWhitespace()->validate($params["time"]) || !v::numeric()->validate($params["idUnidad"])){
         throw new Exception();
     }
 $date=$params["date"]; //con formato dd/mm/aaaa
 $time=$params["time"];//con formato hh:mm:ss
 $idUnidad=$params["idUnidad"]; //integer

if($idUnidad==1){
    $params["result"]=true;
}
else{
    if($idUnidad==2){
        $params["result"]=false;
    }
    else{
        (rand(5, 15)%2<>0)?$params["result"]=true:$params["result"]=false;
    }
}
 
 $response->getBody()->write(json_encode($params));//
     
 } catch (Exception $exc) {
     return $response->withStatus(400)
            ->withHeader('Content-Type', 'text/html')
            ->write($exc->getMessage());
     
 }


 return $response;
});
