<?php
$cve_id = "CVE-2024-21412"; // Example CVE
$url = "https://msrc.microsoft.com/update-guide/vulnerability/$cve_id";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$html = curl_exec($ch);
curl_close($ch);

echo "Fetched HTML length: " . strlen($html) . "\n";

$dom = new DOMDocument();
@$dom->loadHTML($html);
$xpath = new DOMXPath($dom);

// Let's see what meaningful containers exist. Microsoft usually uses SPAs (React/Angular) for their update guide.
// We might need to check if the data is actually in the HTML or loaded via JS.
$scripts = $xpath->query('//script');
echo "Found " . $scripts->length . " scripts.\n";

$main_content = $xpath->query('//div[contains(@class, "cve-content")] | //main | //article');
if ($main_content->length > 0) {
    echo "Found semantic data container.\n";
    $content = $dom->saveHTML($main_content->item(0));
    echo substr(strip_tags($content), 0, 1000) . "\n";
}
else {
    echo "Could not find semantic container. Maybe it's a JSON blob inside a script tag?\n";
    foreach ($scripts as $script) {
        if (strpos($script->nodeValue, 'window.__INITIAL_STATE__') !== false || strpos($script->nodeValue, '{"cveNumber"') !== false) {
            echo "Found interesting script tag with length: " . strlen($script->nodeValue) . "\n";
            echo substr($script->nodeValue, 0, 500) . "...\n";
        }
    }
}
?>
