<?php
header("Content-Type: text/plain");
$b = file_get_contents("php://input");
echo "BODYLEN=" . strlen($b) . "\n";
echo "BODY=" . $b . "\n";
