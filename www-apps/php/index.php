<?php
header("Content-Type: text/plain; charset=utf-8");
echo "hello from php sample\n";
echo "APP_HELLO=" . getenv("APP_HELLO") . "\n";
