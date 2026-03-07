<?php
$cve_id = "CVE-2024-21412";
$url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$cve_id";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0");
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$json = curl_exec($ch);
curl_close($ch);

$data = json_decode($json, true);
// Dump keys and structure
function print_struct($arr, $indent = "")
{
    foreach ($arr as $k => $v) {
        if (is_array($v)) {
            echo $indent . "[$k] (Array count: " . count($v) . ")\n";
            if (!empty($v) && is_int(key($v))) { // Sequential array
                print_struct($v[0], $indent . "  ");
            }
            else {
                print_struct($v, $indent . "  ");
            }
        }
        else {
            $val = substr((string)$v, 0, 50);
            echo $indent . "[$k] => $val...\n";
        }
    }
}
print_struct($data);
?>
