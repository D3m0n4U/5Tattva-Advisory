<?php
// scraper_linux.php
// Fetches latest security notices from Ubuntu USN RSS Feed

require_once 'db.php';

function fetch_linux_advisories($silent = false)
{
    $total_new = 0;
    $total_processed = 0;

    $ubuntu_res = fetch_ubuntu_usn($silent);
    $total_new += $ubuntu_res['new'] ?? 0;
    $total_processed += $ubuntu_res['processed'] ?? 0;

    $rhel_res = fetch_rhel_rhsa($silent);
    $total_new += $rhel_res['new'] ?? 0;
    $total_processed += $rhel_res['processed'] ?? 0;

    return ["status" => "success", "new" => $total_new, "processed" => $total_processed];
}

function fetch_ubuntu_usn($silent = false)
{
    // Ubuntu Security Notices RSS
    $url = "https://ubuntu.com/security/notices/rss.xml";

    if (!$silent)
        echo "Fetching Ubuntu (USN) from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $xml_content = @file_get_contents($url, false, $context);

    if ($xml_content === false) {
        if (!$silent)
            echo "Failed to fetch Ubuntu (USN) RSS Feed.<br>";
        return ["status" => "error", "message" => "Failed to fetch Ubuntu RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        return ["status" => "error", "message" => "Invalid Ubuntu XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $title = (string)$item->title;
        $link = (string)$item->link;
        $description_html = (string)$item->description;
        $pubDate = (string)$item->pubDate;

        $issue_date = date('Y-m-d', strtotime($pubDate));
        $description = strip_tags($description_html);

        $pseudo_id = "USN-" . md5($link);
        if (preg_match('/USN-\d+-\d+/i', $title, $matches)) {
            $pseudo_id = $matches[0];
        }

        $severity = 'High';
        if (stripos($title, 'critical') !== false || stripos($description, 'critical') !== false) {
            $severity = 'Critical';
        }
        elseif (stripos($description, 'low severity') !== false) {
            $severity = 'Low';
        }

        // Fetch the full article HTML to get complete description
        $html = @file_get_contents($link, false, $context);
        if ($html !== false) {
            $dom = new DOMDocument();
            @$dom->loadHTML($html);
            $xpath = new DOMXPath($dom);

            $h1s = $xpath->query('//h1');
            if ($h1s->length > 0) {
                $parent = $h1s->item(0)->parentNode;
                while ($parent && $parent->nodeName !== 'main' && strpos($parent->getAttribute('class'), 'inner-wrapper') === false && $parent->nodeName !== 'body') {
                    $parent = $parent->parentNode;
                }

                if ($parent) {
                    $links = $xpath->query('.//a', $parent);
                    $base_domain = 'https://ubuntu.com';
                    foreach ($links as $a) {
                        $href = $a->getAttribute('href');
                        if (!empty($href) && !preg_match('/^https?:\/\//i', $href) && strpos($href, '#') !== 0 && strpos($href, 'mailto:') !== 0) {
                            $new_href = strpos($href, '/') === 0 ? $base_domain . $href : $base_domain . '/' . ltrim($href, '/');
                            $a->setAttribute('href', $new_href);
                        }
                    }

                    $content_html = $dom->saveHTML($parent);
                    $content_html = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', "", $content_html);
                    $content_html = preg_replace('/<style\b[^>]*>(.*?)<\/style>/is', "", $content_html);
                    $content_html = preg_replace('/<nav\b[^>]*>(.*?)<\/nav>/is', "", $content_html);
                    $content_html = preg_replace('/<ol[^>]*class="[^"]*breadcrumbs[^"]*"[^>]*>(.*?)<\/ol>/is', "", $content_html);
                    $content_html = str_replace("Open side navigation", "", $content_html);
                    $content_html = preg_replace('/<h1[^>]*>.*?<\/h1>/is', "", $content_html);
                    $content_html = preg_replace('/<p[^>]* class="[^"]*p-heading--[1-6][^"]*"[^>]*>(.*?)<\/p>/is', "<h3>$1</h3>", $content_html);
                    $content_html = preg_replace('/<h3[^>]*>\s*Publication date\s*<\/h3>/is', "", $content_html);
                    $content_html = preg_replace('/<p[^>]*>\s*[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4}\s*<\/p>/is', "", $content_html);
                    $content_html = preg_replace('/<h3[^>]*>\s*Have additional questions\?\s*<\/h3>\s*<h3[^>]*>.*?Talk to a member of the team.*?<\/h3>/is', "", $content_html);
                    $content_html = preg_replace('/<button[^>]*>.*?<\/button>/is', "", $content_html);
                    $content_html = preg_replace('/<ul[^>]*class="[^"]*truncated[^"]*"[^>]*>.*?<\/ul>/is', "", $content_html);
                    $content_html = preg_replace('/<[hH][1-6][^>]*>\s*Reduce your security exposure\.?\s*<\/[hH][1-6]>\s*<p[^>]*>.*?Ubuntu Pro provides ten-year security coverage.*?<\/p>\s*<p[^>]*>.*?Get Ubuntu Pro.*?<\/p>/is', "", $content_html);

                    $clean_html = strip_tags($content_html, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote>');
                    $clean_html = preg_replace('/Reduce your security exposure.*?Get Ubuntu Pro/is', '', $clean_html);
                    $clean_html = preg_replace('/(\n\s*){3,}/', "\n\n", $clean_html);

                    if (!empty(trim($clean_html))) {
                        $description = trim($clean_html);
                    }
                }
            }
        }

        $details = [
            ':source_id' => $pseudo_id,
            ':source' => 'Linux',
            ':title' => $title,
            ':severity' => $severity,
            ':issue_date' => $issue_date,
            ':description' => $description,
            ':software_affected' => 'Ubuntu Packages',
            ':solution' => 'Update affected packages via apt-get',
            ':original_link' => $link
        ];

        if (save_advisory($details)) {
            $new_count++;
            if (!$silent) echo "Saved Ubuntu: $pseudo_id<br>\n";
        } else {
            if (!$silent) echo "Skipped Ubuntu (Duplicate): $pseudo_id<br>\n";
        }

        $processed++;
        if ($processed >= 20) break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

function fetch_rhel_rhsa($silent = false)
{
    // RHEL RHSA RSS for discovery
    $rss_url = "https://access.redhat.com/security/data/metrics/rhsa.rss";

    if (!$silent)
        echo "Fetching Red Hat (RHSA) RSS from: $rss_url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n",
            'timeout' => 15
        ]
    ]);

    $xml_content = @file_get_contents($rss_url, false, $context);

    if ($xml_content === false) {
        if (!$silent)
            echo "Failed to fetch RHEL RSS Feed.<br>";
        return ["status" => "error", "message" => "Failed to fetch RHEL RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        return ["status" => "error", "message" => "Invalid RHEL XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $raw_title = (string)$item->title;
        $link = (string)$item->link;
        $pubDate = (string)$item->pubDate;
        $issue_date = date('Y-m-d', strtotime($pubDate));

        // Discover RHSA ID
        $rhsa_id = "";
        if (preg_match('/^(RHSA-\d+:\d+)/i', $raw_title, $m)) {
            $rhsa_id = $m[1];
        } else {
            $rhsa_id = "RHSA-" . md5($link);
        }

        // --- STAGE 2: Fetch Highly Detailed JSON from Red Hat CSAF API ---
        $api_url = "https://access.redhat.com/hydra/rest/securitydata/csaf/" . $rhsa_id . ".json";
        
        if (!$silent) echo "Fetching CSAF details for $rhsa_id... ";
        
        $json_content = @file_get_contents($api_url, false, $context);
        $csaf = $json_content ? json_decode($json_content, true) : null;

        if ($csaf) {
            // Full description extraction from notes
            $topic = "";
            $details_text = "";
            $solution = "Update affected packages via dnf or yum";

            if (isset($csaf['document']['notes'])) {
                foreach ($csaf['document']['notes'] as $note) {
                    $category = strtolower($note['category'] ?? '');
                    if ($category === 'summary' || $category === 'description') {
                        $details_text .= (empty($details_text) ? "" : "\n\n") . $note['text'];
                    } elseif ($category === 'general' && stripos($note['title'] ?? '', 'topic') !== false) {
                        $topic = $note['text'];
                    } elseif (stripos($category, 'remediation') !== false || stripos($note['title'] ?? '', 'solution') !== false) {
                        $solution = $note['text'];
                    }
                }
            }

            $title = $csaf['document']['title'] ?? $raw_title;
            
            // Extract Affected Products from product_tree recursively
            $affected_products = [];
            $extract_products = function($branches) use (&$affected_products, &$extract_products) {
                foreach ($branches as $branch) {
                    if (($branch['category'] ?? '') === 'product_name') {
                        $affected_products[] = $branch['name'] ?? '';
                    }
                    if (isset($branch['branches'])) {
                        $extract_products($branch['branches']);
                    }
                }
            };
            
            if (isset($csaf['product_tree']['branches'])) {
                $extract_products($csaf['product_tree']['branches']);
            }
            $software_affected = !empty($affected_products) ? implode(', ', array_unique($affected_products)) : 'Red Hat Enterprise Linux';

            // Extract CVEs
            $cve_ids = [];
            if (isset($csaf['vulnerabilities'])) {
                foreach ($csaf['vulnerabilities'] as $v) {
                    if (isset($v['cve'])) $cve_ids[] = $v['cve'];
                }
            }
            $cve_string = implode(',', array_unique($cve_ids));

            // Determine Dashboard Severity
            $severity = "Medium";
            if (isset($csaf['document']['aggregate_severity']['text'])) {
                $rhel_severity = $csaf['document']['aggregate_severity']['text'];
                switch (strtolower($rhel_severity)) {
                    case 'critical': $severity = 'Critical'; break;
                    case 'important': $severity = 'High'; break;
                    case 'moderate': $severity = 'Medium'; break;
                    case 'low': $severity = 'Low'; break;
                }
            }

            // Construct Rich HTML Description
            $rich_description = "";
            if (!empty($topic)) $rich_description .= "<h3>Topic</h3><p>" . nl2br(htmlspecialchars($topic)) . "</p>";
            if (!empty($details_text)) $rich_description .= "<h3>Description</h3><p>" . nl2br(htmlspecialchars($details_text)) . "</p>";

            $details = [
                ':source_id' => $rhsa_id,
                ':source' => 'Linux',
                ':title' => $title,
                ':severity' => $severity,
                ':issue_date' => $issue_date,
                ':description' => $rich_description,
                ':software_affected' => $software_affected,
                ':solution' => $solution,
                ':original_link' => $link,
                ':cve_ids' => $cve_string
            ];
        } else {
            // Fallback to RSS data if API fails
            if (!$silent) echo "(API Failed, using RSS Fallback) ";
            
            $severity = 'Medium';
            if (preg_match('/Important|Critical/i', $raw_title)) $severity = 'High';

            $details = [
                ':source_id' => $rhsa_id,
                ':source' => 'Linux',
                ':title' => $raw_title,
                ':severity' => $severity,
                ':issue_date' => $issue_date,
                ':description' => (string)$item->description,
                ':software_affected' => 'Red Hat Enterprise Linux',
                ':solution' => 'Update affected packages via dnf or yum',
                ':original_link' => $link
            ];
        }

        if (save_advisory($details)) {
            $new_count++;
            if (!$silent) echo "Saved RHEL: $rhsa_id<br>\n";
        } else {
            if (!$silent) echo "Skipped RHEL (Duplicate/Update): $rhsa_id<br>\n";
        }

        $processed++;
        if ($processed >= 15) break; // Fetching full details for 15 is plenty per cycle
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

// Allow CLI execution only if directly called
if (php_sapi_name() === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    $result = fetch_linux_advisories(false);
    print_r($result);
}
?>
