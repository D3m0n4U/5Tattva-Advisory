<?php
$url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a";

echo "Fetching: $url\n";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Important for CISA
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
$html = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "Fetched length: " . strlen($html) . "\n";
echo "HTTP Code: $http_code\n";

if (strlen($html) < 1000) {
    echo "Raw HTML:\n$html\n";
}
else {
    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    $xpath = new DOMXPath($dom);

    // Let's look for article body 
    $nodes = $xpath->query('//article | //div[contains(@class, "c-article__body")] | //div[contains(@class, "l-content")] | //div[contains(@id, "main-content")]');

    if ($nodes->length > 0) {
        echo "Found main content container.\n";
        $content = $dom->saveHTML($nodes->item(0));
        echo substr(strip_tags($content), 0, 1000) . "...\n";
    }
    else {
        echo "Could not find a main article container.\n";
    }
}
?>
