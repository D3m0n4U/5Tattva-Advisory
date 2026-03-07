<?php
// scraper_cisa.php
// Fetches latest alerts from CISA RSS Feed

require_once 'db.php';

function fetch_cisa_advisories($silent = false)
{
    // Basic RSS feed for CISA cybersecurity alerts
    $url = "https://www.cisa.gov/cybersecurity-advisories/all.xml";

    if (!$silent)
        echo "Fetching CISA from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $xml_content = @file_get_contents($url, false, $context);

    if ($xml_content === false) {
        if (!$silent)
            echo "Failed to fetch CISA RSS Feed.<br>";
        return ["status" => "error", "message" => "Failed to fetch CISA RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        return ["status" => "error", "message" => "Invalid CISA XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $title = (string)$item->title;
        $link = (string)$item->link;
        $description = (string)$item->description;
        $pubDate = (string)$item->pubDate;

        $issue_date = date('Y-m-d', strtotime($pubDate));

        // Generate a pseudo-ID or extract from link
        // Example link: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
        preg_match('/([a-z0-9-]+)$/i', parse_url($link, PHP_URL_PATH), $matches);
        $pseudo_id = isset($matches[1]) ? strtoupper($matches[1]) : 'CISA-' . md5($link);
        if (!str_starts_with($pseudo_id, 'AA') && !str_starts_with($pseudo_id, 'CISA')) {
            $pseudo_id = "CISA-" . $pseudo_id;
        }


        // Deduce severity (CISA alerts are usually High/Critical by nature, let's default to High)
        $severity = 'High';
        if (stripos($title, 'critical') !== false || stripos($description, 'critical') !== false) {
            $severity = 'Critical';
        }

        // Parse and clean CISA RSS description (which contains the full advisory HTML)
        $rich_description = '';
        if (!empty($description)) {
            $temp_dom = new DOMDocument();
            @$temp_dom->loadHTML('<?xml encoding="utf-8" ?><body>' . $description . '</body>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
            $xpath = new DOMXPath($temp_dom);

            // Fix links
            $links = $temp_dom->getElementsByTagName('a');
            foreach ($links as $a) {
                $href = $a->getAttribute('href');
                if (!empty($href) && !preg_match('/^https?:\/\//i', $href) && strpos($href, '#') !== 0 && strpos($href, 'mailto:') !== 0 && strpos($href, 'javascript:') !== 0) {
                    $new_href = strpos($href, '/') === 0 ? 'https://www.cisa.gov' . $href : 'https://www.cisa.gov/' . ltrim($href, '/');
                    $a->setAttribute('href', $new_href);
                }
                $a->setAttribute('target', '_blank');
            }

            $body = $temp_dom->getElementsByTagName('body')->item(0);
            if ($body) {
                foreach ($body->childNodes as $child) {
                    $rich_description .= $temp_dom->saveHTML($child);
                }
            }

            // CISA's RSS contains formatting but also garbage elements. Let's strip it to semantic tags.
            $rich_description = strip_tags($rich_description, '<h1><h2><h3><h4><h5><h6><p><br><ul><li><ol><strong><em><a><table><tr><td><th><tbody><thead><pre><code><blockquote><div><span>');
        }

        // Construct standard data format
        $details = [
            ':source_id' => $pseudo_id,
            ':source' => 'CISA',
            ':title' => $title,
            ':severity' => $severity,
            ':issue_date' => $issue_date,
            ':description' => $rich_description, // CISA RSS description is now cleaned HTML 
            ':software_affected' => 'See description',
            ':solution' => 'See original CISA advisory',
            ':original_link' => $link
        ];

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved CISA: $pseudo_id<br>\n";
        }
        else {
            if (!$silent)
                echo "Skipped CISA (Duplicate): $pseudo_id<br>\n";
        }

        $processed++;

        if ($processed >= 20)
            break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

if (php_sapi_name() === 'cli') {
    $result = fetch_cisa_advisories(false);
    print_r($result);
}
?>
