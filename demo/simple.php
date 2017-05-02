<?php

include_once dirname(__DIR__) . '/vendor/autoload.php';

$security = new \Bavix\Security\Security(__FILE__);

$data = $security->encrypt('hello world');

var_dump($data, $security->decrypt($data));
