<?php
$cve_id = "CVE-2024-21412";
$url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$cve_id";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0");
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$json = curl_exec($ch);
curl_close($ch);

$data = json_decode($json, true);
$rich_description = '';

if ($data) {
    // 1. Executive Summary / Description
    $summary = $data['unformattedDescription'] ?? '';
    // Let's see if there is an article of type "Executive Summary"
    foreach ($data['articles'] ?? [] as $article) {
        if (isset($article['articleType']) && strtolower($article['articleType']) === 'executive summary') {
            if (!empty($article['description'])) {
                $summary = $article['description'];
            }
        }
    }

    if (!empty($summary)) {
        $rich_description .= "<h3>Executive Summary</h3>" . $summary;
    }

    // 2. Metrics 
    if (isset($data['baseScore']) && isset($data['vectorString'])) {
        $rich_description .= "<h3>Metrics</h3>";
        $rich_description .= "<p><strong>Base Score:</strong> " . htmlspecialchars($data['baseScore']) . " | <strong>Severity:</strong> " . htmlspecialchars($data['severity'] ?? 'N/A') . "</p>";
        $rich_description .= "<p><strong>Vector:</strong> " . htmlspecialchars($data['vectorString']) . "</p>";
    }

    // 3. FAQs
    $faq_html = "";
    foreach ($data['articles'] ?? [] as $article) {
        if (isset($article['articleType']) && strtolower($article['articleType']) === 'faq') {
            if (!empty($article['description'])) {
                $faq_html .= $article['description'] . "<br>";
            }
        }
    }
    if (!empty($faq_html)) {
        $rich_description .= "<h3>FAQ</h3>" . $faq_html;
    }

    // 4. Mitigations
    $mit_html = "";
    foreach ($data['articles'] ?? [] as $article) {
        if (isset($article['articleType']) && strtolower($article['articleType']) === 'mitigation') {
            if (!empty($article['description'])) {
                $mit_html .= $article['description'] . "<br>";
            }
        }
    }
    if (!empty($mit_html)) {
        $rich_description .= "<h3>Mitigations</h3>" . $mit_html;
    }

    // Strip unsafe tags while keeping formatting
    $rich_description = strip_tags($rich_description, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote><div><span>');

    echo "==== EXTRACTED RICH HTML ====\n\n";
    echo $rich_description;
}
?>
