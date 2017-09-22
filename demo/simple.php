<?php

include_once dirname(__DIR__) . '/vendor/autoload.php';

$security = new \Bavix\Security\Security(__FILE__);
$tmp = new \Bavix\Security\Salted(__FILE__);

$data1 = $security->encrypt('hello world');
$data2 = $tmp->encrypt('hello world');

var_dump($data1, $data2);
