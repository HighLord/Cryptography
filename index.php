<?php

/** Comment 1
 *  Preventing unathorized hotlinking
 */
$response = array
(
    "status"=>"404",      
    "data"=>"unknown endpoint"
);
$data = json_encode($response);
die($data); 