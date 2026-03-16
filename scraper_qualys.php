<?php
// scraper_qualys.php
// Fetches high-fidelity research advisories from Qualys Security Blog RSS

require_once 'db.php';

function fetch_qualys_advisories($silent = false)
{
    $url = "https://blog.qualys.com/feed";

    if (!$silent)
        echo "Fetching Qualys Blog RSS from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $xml_content = @file_get_contents($url, false, $context);

    if ($xml_content === false) {
        if (!$silent)
            echo "Failed to fetch Qualys RSS Feed.<br>";
        return ["status" => "error", "message" => "Failed to fetch Qualys RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        return ["status" => "error", "message" => "Invalid Qualys XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $title = (string)$item->title;
        $link = (string)$item->link;
        $pubDate = (string)$item->pubDate;
        
        // Use content:encoded for high-fidelity description if available
        $namespaces = $item->getNamespaces(true);
        $content_encoded = '';
        if (isset($namespaces['content'])) {
            $content_encoded = (string)$item->children($namespaces['content'])->encoded;
        }
        
        $description = !empty($content_encoded) ? $content_encoded : (string)$item->description;

        $issue_date = date('Y-m-d', strtotime($pubDate));

        // Generate ID from link
        // Example: https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-...
        $pseudo_id = "QUALYS-" . strtoupper(md5($link));
        if (preg_match('/([a-z0-9-]+)$/i', parse_url($link, PHP_URL_PATH), $matches)) {
            $pseudo_id = "QUALYS-" . strtoupper($matches[1]);
        }

        // Determine severity (blog posts are often about high-impact research)
        $severity = 'High';
        if (stripos($title, 'critical') !== false || stripos($description, 'critical') !== false || stripos($description, 'root') !== false) {
            $severity = 'Critical';
        }

        // Clean and prepare rich description
        $rich_description = strip_tags($description, '<h1><h2><h3><h4><h5><h6><p><br><ul><li><ol><strong><em><a><table><tr><td><th><tbody><thead><pre><code><blockquote><div><span>');

        // Construct standard data format
        $details = [
            ':source_id' => $pseudo_id,
            ':source' => 'Qualys',
            ':title' => $title,
            ':severity' => $severity,
            ':issue_date' => $issue_date,
            ':description' => $rich_description,
            ':software_affected' => 'See research details',
            ':solution' => 'Apply latest security patches as recommended in Qualys Research',
            ':original_link' => $link
        ];

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved Qualys (Blog): $pseudo_id<br>\n";
        }
        else {
            if (!$silent)
                echo "Skipped Qualys (Duplicate/Old): $pseudo_id<br>\n";
        }

        $processed++;

        if ($processed >= 15)
            break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

// Allow CLI execution only if directly called
if (php_sapi_name() === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    $result = fetch_qualys_advisories(false);
    print_r($result);
}
?>
