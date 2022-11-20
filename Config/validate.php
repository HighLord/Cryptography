<?php

$_SERVER = apache_request_headers();

/** Comment 1
 *  The token we created earlier in the authorization file should either be passed in the header or as a cookie called token
 *  otherwise the user will receive a 400 unathorized code
 */
if (isset($_SERVER['Authorization']))
{
    $token = $_SERVER['Authorization'];    
} 
else if (isset($_COOKIE["token"]))
{
    $token = $_COOKIE["token"];    
} 
else 
{
    $response = array
    (
    "Status"=>"400",      
    "data"=>"You are not Authorized to access this endpoint"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 1) 
    {
        die($datas);
    }
    return($datas);
} 
$token = json_decode(base64_decode($token));
$hash_key = $token->dynamic_key;
$data = $token->data;

function decrypt($base)
{
    $ciphering = "AES-256-CTR";
    $iv_length = openssl_cipher_iv_length($ciphering);
    $options = 2;
    $public_key = 'AC_CHOOSEYOUROWNKEY-THELONGERTHEBETTER_1'; //must be the same key as in the authorization file
    $private_key = md5($public_key);
    $decryption = openssl_decrypt($base, $ciphering, $private_key, $options, $iv_length, $public_key);
    return $decryption;
}
$dynamic_key = decrypt($hash_key);

/** Comment 2
 *  The dynamic key is gotten from the decrypted hash_key which is then used to decrypt your data
 */
function data($hash, $string)
{
    $ciphering = "AES-256-CTR";
    $iv_length = openssl_cipher_iv_length($ciphering);
    $options = 2;
    $public_key = $hash;
    $private_key = md5($hash);
    $encryption = openssl_decrypt($string, $ciphering, $private_key, $options, $iv_length, $public_key);
    return $encryption;   
}

$data = data($dynamic_key, $data);
$data = json_decode($data);
$user_name = $data->user_name;
$user_pass = $data->user_pass;
$validity = $data->validity;
$md5 = $data->md5;
$randomizer = $data->randomizer;
$current_date = strtotime(date("Y-m-d H:i:s"));
$dynamic_key_md5 = md5($dynamic_key);

/** Comment 3
 *  Here, as an added measure, we can check if the dynamic key matches the randomizer we stored earlier on.
 *  If it does, then it wasnt tampered with, but if it doesn't, then we terminate
 */
if ($dynamic_key_md5 !== $randomizer)
{
    $response = array
    (
    "Status"=>"400",      
    "data"=>"You are not Authorized to access this endpoint"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 2) 
    {
        die($datas);
    }
    return($datas);
}

/** Comment 4
 *  We can now crosscheck the current date from the time we granted the authorization token
 *  If the current time has passed the time we allocated to the token, then its expired
 */
if ($current_date > $validity)
{
    $response = array
    (
        "Status"=>"401",      
        "data"=>"Your Authorization has expired"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 2) 
    {
        die($datas);
    }
    return($datas);
}

/** Comment 5
 *  If all checks has passed, you can then validate the user login details passed in our token data
 *  We can fetch the token_access we stored earlier in our database and check if its the same with the timeline in our token
 *  This prevents mitm attacks. (for if a user uses an open wifi and an attacker grabs the users token, all the user has to do is re-login)
 */
include_once '../config/database.php';
$sql = "SELECT user_login, user_pass, token_access, user_public_api, user_secret_key, ID FROM binance_users WHERE user_email='$user_name' AND user_pass='$user_pass'";
$result = $conn->query($sql);
if (mysqli_num_rows($result) === 1)
{
    $row = $result->fetch_assoc();
    $token_access = $row['token_access'];
    $user_public_api = $row['user_public_api'];
    $user_secret_key = $row['user_secret_key'];
    $id = $row['ID'];
    if ($token_access !== $validity || $md5 !== md5($user_name.$user_pass.$validity))
    {
    $response = array
    (
            "Status"=>"402",
            "data"=>"Your Authorization token is invalid"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 2) 
    {
        die($datas);
    }
    return($datas);    
    }
    header('Authorization: Confirmed');
    $response = array
    (
        "Status"=>"200",
        "userid"=>"$id",
        "data"=>"Logged in successfully"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 2) 
    {
        echo($datas);
    }
    return($datas);
} 
else 
{
    $response = array
    (
        "Status"=>"403",      
        "data"=>"Incorrect Login details"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) == 2) 
    {
        die($datas);
    }
    return($datas);
}
