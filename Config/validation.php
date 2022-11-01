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
function validate($datas)
{
    $CAPSdatas = (strtolower($datas));

    /** Comment 2
     *  The variable $check contains a list of characters i dont want the user to use
     *  you can edit and add/remove yours
     */
    $check = "select % \ / insert - * ' = < > ( ) , \"";
    $array = (preg_split('/\s+/', $check));
    foreach($array as $item) 
    {
        if (strpos($CAPSdatas, $item)) 
        {
            /** Comment 3
             *  The variable $items contain what word was found by the security rules
             *  I added it their incase you need it
             */
            $items = $item;
            $try = (strlen($item));
        }
    }
if (isset($try))
{
    $data = "This request was blocked by the security rules";  
    $response = array
    (
        "Status"=>"403",      
        "data"=>"$data"
    );
    $data = json_encode($response);
    die($data);
}
    /** Comment 4
     *  For added security, if none of the characters were found, we can still do a normal character stripping
     */
    $datas = trim($datas);
    $datas = stripslashes($datas);
    $datas = htmlspecialchars($datas);
    $datas = htmlentities($datas);
    return $datas;
}