<?php
$cve_id = "CVE-2024-21412";
$url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$cve_id";

echo "Fetching: $url\n";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0");
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$json = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "HTTP Code: $http_code\n";
if ($http_code === 200 && $json) {
    $data = json_decode($json, true);
    // Let's see what rich text fields we get
    echo "Summary: " . substr(print_r($data['executiveSummary'] ?? 'N/A', true), 0, 200) . "\n";
    echo "Description: " . substr(print_r($data['unformattedDescription'] ?? 'N/A', true), 0, 200) . "\n";
    echo "FAQ count: " . count($data['faqs'] ?? []) . "\n";
    echo "Mitigation count: " . count($data['mitigations'] ?? []) . "\n";
    echo "Workaround count: " . count($data['workarounds'] ?? []) . "\n";
    echo "Revisions count: " . count($data['revisions'] ?? []) . "\n";

    // Print a raw bit to see HTML structuring capabilities
    if (isset($data['faqs'][0])) {
        echo "FAQ 1 Q: " . $data['faqs'][0]['question'] . "\n";
        echo "FAQ 1 A: " . $data['faqs'][0]['answer'] . "\n";
    }
}
else {
    echo "Failed to fetch or invalid JSON.\n";
}
?>
