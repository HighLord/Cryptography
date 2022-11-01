<?php

/** Comment 1
 *  The below code prevents a user from hotlinking directly to this file.
 *  This file has to be included once wherever it is needed.
 */
if (count(get_included_files()) == 1)
{
    require_once '../index.php';
    die();
}
$token = "token";
if (isset($_POST['username']) and isset($_POST['password']))
{
    /** Comment 2
     *  We create a random string of 64 length
     */
    function random_str
    (
        int $length = 64,
        string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ): string
    {
        if ($length < 1)
        {
            die("Length must be a positive integer");
        }
        $pieces = [];
        $max = strlen($keyspace) - 1;
        for ($i = 0; $i < $length; ++$i) {
            $pieces []= $keyspace[random_int(0, $max)];
        }
        return implode('', $pieces);
    }

    /** Comment 3
     *  First we get the time the authorization request was made
     *  So we can check what time that particular authorization should expire
     *  Then we can add whatever time we want the token to be valid for to it. default is 3600 seconds.
     */
    date_default_timezone_set("Africa/Lagos");
    $date_issued = strtotime(date("Y-m-d H:i:s"));
    require_once 'config/validation.php';
    $expire = $date_issued + 3600;

    /** Comment 4
     *  The validate function uses a previous function i made @https://github.com/HighLord/validation
     *  This function, while not required is used to filter out certain keywords from the form
     */ 
    $user_name = validate($_POST['username']);
    $user_pass = validate($_POST['password']);
    $random_string = random_str();

    /** Comment 5
     *  Database Login Config
     */
    require_once 'config/database.php';
    $sql = "SELECT user_login, user_pass, token_access, ID FROM database_users WHERE user_email='$user_name' AND user_pass='$user_pass'";
    $result = $conn->query($sql);
    if (mysqli_num_rows($result) === 1)
    {
        $sql = "UPDATE binance_users SET token_access='$expire' WHERE user_email='$user_name' AND user_pass='$user_pass'";
        $result = $conn->query($sql);
        $conn->close();
    } else 
    {
        $response = array(
        "Status"=>"403",      
        "data"=>"Incorrect Login details"
    );
    $datas = json_encode($response);
    if (count(get_included_files()) >= 1) 
    {
        die($datas);
    }
    return($datas);
    }
    function salt($string)
    {
        $ciphering = "AES-128-CTR";
        $iv_length = openssl_cipher_iv_length($ciphering);
        $options = 0;
        $public_key = 'AC_CHOOSEYOUROWNKEY-THELONGERTHEBETTER_1';
        $private_key = md5($public_key);
        $encryption = openssl_encrypt($string, $ciphering, $private_key, $options, $public_key);
        return $encryption;   
    }

    /** Comment 6
     *  We encrypt the random string generated earlier @ comment 2
     */
    $hash_string = salt($random_string);
    $randomizer = md5($random_string);

    /** Comment 7
     *  We then encrypt the user login details, password, the time the user got the authorization login and a random MD5 string
     *  Please note that the job of randomizer is to make the final encrypted output always change.
     *  This way, anyone in possesion of the authorization hash cannot login once the user logs in
     */
    function encrypt($hash_string, $random_string, $user_name, $user_pass, $expire, $randomizer)
    {
        $data1 = array
        (
            "user_name"=>"$user_name",
            "user_pass"=>"$user_pass",
            "validity"=>"$expire",
            "randomizer"=>"$randomizer"
        );
         $data = json_encode($data1);
         $ciphering = "AES-128-CTR";
         $iv_length = openssl_cipher_iv_length($ciphering);
         $options = 0;
         $public_key = $random_string;
         $private_key = md5($random_string);
         $encryption = openssl_encrypt($data, $ciphering, $private_key, $options, $public_key);
        
        $data = array
        (
            "dynamic_key"=>"$hash_string",
            "data"=>"$encryption"
        ); 
        $cryptograph = base64_encode(json_encode($data));    
        return $cryptograph; 
        }
    $base = encrypt($hash_string, $random_string, $user_name, $user_pass, $expire, $randomizer);

    /** Comment 8
     *  You can then set the final encrypted output as your cookie
     *  To get the output in your browser requests, one way is to use an authorization header
     *  and then pass the cookie into the header and make sure all requests search for that header value before processing
     */
    $token_value = "$base";
    setcookie($token, $token_value, time() + (3600), '/', ".AC_Yourwebsite_1.com", 1);
    return $base;
}