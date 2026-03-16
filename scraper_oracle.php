<?php
// scraper_oracle.php
// Fetches latest security advisories from Oracle RSS Feed

require_once 'db.php';

function fetch_oracle_advisories($silent = false)
{
    $rss_url = "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml";

    if (!$silent)
        echo "Fetching Oracle Advisories from: $rss_url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        ]
    ]);

    $xml_content = @file_get_contents($rss_url, false, $context);
    if ($xml_content === false) {
        $error = error_get_last();
        if (!$silent)
            echo "Failed to fetch Oracle RSS Feed. Error: " . ($error['message'] ?? 'Unknown') . "<br>";
        return ["status" => "error", "message" => "Failed to fetch Oracle RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        if (!$silent)
            echo "Invalid Oracle XML response.<br>";
        return ["status" => "error", "message" => "Invalid Oracle XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $title = trim((string)$item->title);
        $link = trim((string)$item->link);
        $pubDate = trim((string)$item->pubDate);
        
        // Oracle URLs sometimes have parameters or fragments, clean them if needed
        $clean_link = strtok($link, '#');
        $issue_date = date('Y-m-d', strtotime($pubDate));
        
        // Unique ID based on the filename
        $filename = pathinfo(parse_url($clean_link, PHP_URL_PATH), PATHINFO_FILENAME);
        $pseudo_id = "ORCL-" . strtoupper($filename);
        
        // Fallback for non-standard URLs
        if (empty($filename) || $filename == 'security-alerts') {
            $pseudo_id = "ORCL-" . md5($clean_link);
        }

        if (!$silent)
            echo "Processing Oracle: $title ($pseudo_id)...\n<br>";

        // Default content
        $description = $title;
        $solution = "Refer to Oracle Security Advisory for patches and remediation steps.";
        $software_affected = "Oracle Products";
        $severity = "Critical"; // Oracle CPUs usually contain critical patches

        // Fetch detail page for richer content
        $detail_html = @file_get_contents($clean_link, false, $context);
        if ($detail_html === false) {
             $error = error_get_last();
             if (!$silent) 
                 echo " --- Failed to fetch detail: $clean_link. Error: " . ($error['message'] ?? 'Unknown') . "<br>\n";
        } else {
            if (!$silent)
                echo " --- Fetched Detail: " . strlen($detail_html) . " bytes.<br>\n";
            
            $dom = new DOMDocument();
            @$dom->loadHTML('<?xml encoding="UTF-8">' . $detail_html);
            $xpath = new DOMXPath($dom);

            // Broaden selection for comprehensive scraping
            $container_queries = [
                '//div[contains(@class, "otNSection")]',
                '//article',
                '//div[@id="main"]',
                '//div[@class="u10-container"]',
                '//body' // Safe fallback
            ];
            
            $node = null;
            foreach ($container_queries as $q) {
                $results = $xpath->query($q);
                if ($results->length > 0) {
                    $node = $results->item(0);
                    break;
                }
            }
            
            if ($node) {
                // Cleanup unwanted elements while preserving the vast majority of data
                // We are more aggressive with head/nav removal when taking the body
                $to_remove = $xpath->query('.//script | .//style | .//nav | .//footer | .//header | .//div[contains(@class, "u10-header")] | .//div[contains(@class, "u10-footer")] | .//div[contains(@id, "u10")]', $node);
                foreach ($to_remove as $rem) {
                    try {
                        if ($rem->parentNode) {
                            $rem->parentNode->removeChild($rem);
                        }
                    } catch (Exception $e) {}
                }

                // Fix links (Important for complete scraping so users can navigate to sub-matrices)
                $base_url = 'https://www.oracle.com';
                $links = $xpath->query('.//a', $node);
                foreach ($links as $a) {
                    $href = $a->getAttribute('href');
                    if (!empty($href) && !preg_match('/^https?:\/\//i', $href)) {
                        // Handle anchor links vs relative links
                        if (strpos($href, '#') === 0) {
                             // Preserve anchors
                        } else {
                            $a->setAttribute('href', $base_url . (strpos($href, '/') === 0 ? '' : '/') . $href);
                        }
                    }
                }

                $clean_html = $dom->saveHTML($node);
                
                // Capture granular CVSS and CVE details by allowing more tags
                $clean_html = strip_tags($clean_html, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote><span>');
                
                // Trimming to start exactly where the user requested
                $start_markers = ["Affected Products and Patch Information", "Introduction", "Executive Summary", "Critical Patch Update Advisory", "Affected Products and Versions"];
                foreach ($start_markers as $marker) {
                    if (($pos = stripos($clean_html, $marker)) !== false) {
                        $clean_html = substr($clean_html, $pos);
                        break;
                    }
                }
                
                // Professional Header Injection
                // Wrap the primary marker in a professional header
                $clean_html = preg_replace('/(Affected Products and Patch Information)/i', '<h3 class="oracle-section-header">$1</h3>', $clean_html, 1);
                
                // Wrap product family names if they are followed by 'Risk Matrix' or appear as distinct section starts
                $clean_html = preg_replace('/(Oracle (Database|Fusion Middleware|Supply Chain|E-Business Suite|Cloud|Financial Services|Health Sciences|Insurance|Java SE|Retail|Utilities|MySQL) Risk Matrix)/i', '<h3 class="oracle-product-header">$1</h3>', $clean_html);
                
                // Final cleanup of redundant Oracle branding text if it leaked through
                $clean_html = preg_replace('/(Copyright.*?Oracle.*?All Rights Reserved|Oracle is a registered trademark)/i', '', $clean_html);
                
                $description = trim($clean_html);
            }
        }

        // Extract CVEs from description
        $cve_ids = extract_cves($title . ' ' . $description);

        $details = [
            ':source_id' => $pseudo_id,
            ':source' => 'Oracle',
            ':cve_ids' => $cve_ids,
            ':title' => $title,
            ':severity' => $severity,
            ':issue_date' => $issue_date,
            ':description' => $description,
            ':software_affected' => $software_affected,
            ':solution' => $solution,
            ':original_link' => $link
        ];

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved Oracle: $pseudo_id<br>\n";
        } else {
            if (!$silent)
                echo "Skipped/Updated Oracle: $pseudo_id<br>\n";
        }

        $processed++;
        // Remove the small limit to allow complete scraping
        if ($processed >= 100) break; 
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

// Allow CLI execution only if directly called
if (php_sapi_name() === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    $result = fetch_oracle_advisories(false);
    print_r($result);
}
?>
