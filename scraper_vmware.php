<?php
// scraper_vmware.php
// Fetches latest security advisories from Broadcom/VMware API

require_once 'db.php';

function fetch_vmware_advisories($silent = false)
{
    $api_url = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList";
    $segments = ['VC' => 'VMware Cloud Foundation', 'VT' => 'Tanzu', 'VA' => 'Application Networking and Security', 'VE' => 'Software Defined Edge'];
    
    $new_count = 0;
    $processed = 0;

    foreach ($segments as $segment_id => $segment_name) {
        if (!$silent)
            echo "Fetching VMware ($segment_name) from Broadcom API...\n<br>";

        $data = [
            "pageNumber" => 0,
            "pageSize" => 20,
            "searchVal" => "",
            "segment" => $segment_id,
            "sortInfo" => ["column" => "", "order" => ""]
        ];

        $options = [
            'http' => [
                'header'  => "Content-type: application/json\r\nUser-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n",
                'method'  => 'POST',
                'content' => json_encode($data),
            ],
        ];

        $context  = stream_context_create($options);
        $result_json = @file_get_contents($api_url, false, $context);

        if ($result_json === false) {
            if (!$silent)
                echo "Failed to fetch VMware ($segment_name) advisories.<br>";
            continue;
        }

        $result = json_decode($result_json, true);
        if (!$result || !isset($result['success']) || !$result['success'] || !isset($result['data']['list'])) {
            if (!$silent)
                echo "Invalid response for VMware ($segment_name).<br>";
            continue;
        }

        foreach ($result['data']['list'] as $item) {
            $id = $item['advisoryId'] ?? ('VMSA-' . md5($item['title']));
            $title = $item['title'] ?? 'No Title';
            $severity = $item['severity'] ?? 'Medium';
            $published_at = $item['published'] ?? date('Y-m-d');
            $link = $item['notificationUrl'] ?? '';
            
            // Format date to Y-m-d
            $issue_date = date('Y-m-d', strtotime($published_at));

            // Default description
            $description = $item['description'] ?? $title;
            $solution = 'Refer to VMware Security Advisory for patches and workarounds.';
            $software_affected = $segment_name;

            // Fetch full content if link is available
            if (!empty($link)) {
                $full_content = fetch_vmware_detail($link);
                if ($full_content) {
                    $description = $full_content['description'] ?: $description;
                    $solution = $full_content['solution'] ?: $solution;
                    $software_affected = ($full_content['software_affected'] ? $segment_name . ' - ' . $full_content['software_affected'] : $segment_name);
                }
            }
            
            // Extract CVEs from title or description
            $cve_ids = extract_cves($title . ' ' . $description);

            $details = [
                ':source_id' => $id,
                ':source' => 'VMware',
                ':cve_ids' => $cve_ids,
                ':title' => $title,
                ':severity' => ucfirst(strtolower($severity)),
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
                    echo "Saved VMware: $id<br>\n";
            } else {
                // For existing records, we might want to update the description if we now have full content
                if (in_array('VMware', ['VMware'])) { // Just keeping the pattern from db.php
                     global $db;
                     $stmt = $db->prepare('UPDATE advisories SET description = :description, software_affected = :software_affected, solution = :solution WHERE source_id = :source_id AND source = "VMware"');
                     $stmt->execute([
                         ':description' => $description,
                         ':software_affected' => $software_affected,
                         ':solution' => $solution,
                         ':source_id' => $id
                     ]);
                }
                if (!$silent)
                    echo "Updated/Skipped VMware: $id<br>\n";
            }

            $processed++;
            if ($processed >= 40) break; // Total limit across segments for safety
        }
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

function fetch_vmware_detail($url) {
    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $html = @file_get_contents($url, false, $context);
    if ($html === false) return null;

    $dom = new DOMDocument();
    @$dom->loadHTML('<?xml encoding="UTF-8">' . $html);
    $xpath = new DOMXPath($dom);

    $results = [
        'description' => '',
        'software_affected' => '',
        'solution' => ''
    ];

    // Broadcom portal detail content is usually inside .ecx-portlet-area
    $main_content = $xpath->query('//div[contains(@class, "ecx-portlet-area")]');
    if ($main_content->length > 0) {
        $node = $main_content->item(0);
        
        // Remove scripts, styles, and navigation elements
        $to_remove = $xpath->query('.//script | .//style | .//nav | .//header | .//footer', $node);
        foreach ($to_remove as $rem) {
            $rem->parentNode->removeChild($rem);
        }

        // Fix links
        $links = $xpath->query('.//a', $node);
        foreach ($links as $a) {
            $href = $a->getAttribute('href');
            if (!empty($href) && !preg_match('/^https?:\/\//i', $href)) {
                $a->setAttribute('href', 'https://support.broadcom.com' . $href);
            }
        }

        // Try to isolate specific sections
        // The user wants content to start from "Product Release Advisory"
        // Or "Synopsis" / "Introduction" for VMSA pages
        
        $clean_html = $dom->saveHTML($node);
        
        $start_markers = [
            "Product Release Advisory" => '<span class="pra-header">Product Release Advisory</span>',
            "Synopsis" => '<h3>Synopsis</h3>',
            "Introduction" => '<h3>Introduction</h3>',
            "Advisory ID" => '<h3>Advisory Details</h3>',
            "1. Impacted Products" => '<h3>1. Impacted Products</h3>'
        ];

        foreach ($start_markers as $marker => $replacement) {
            // Match the marker even if wrapped in <strong> or with a trailing colon
            $pattern = '/(?:<strong>\s*)?' . preg_quote($marker, '/') . '(?:\s*[:])?(?:\s*<\/strong>)?/i';
            if (preg_match($pattern, $clean_html, $matches, PREG_OFFSET_CAPTURE)) {
                $pos = $matches[0][1];
                $len = strlen($matches[0][0]);
                // Remove everything before the marker
                $clean_html = substr($clean_html, $pos);
                // Replace the marker (and its surrounding bold/colon) with our formatted version
                $clean_html = substr_replace($clean_html, $replacement, 0, $len);
                break;
            }
        }


        
        // Strip layout tags but keep formatting
        $clean_html = strip_tags($clean_html, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote>');
        
        $results['description'] = trim($clean_html);

        
        // Try to extract resolution/solution specifically
        $resolution = $xpath->query('//*[contains(text(), "Resolution")]/following-sibling::*', $node);
        if ($resolution->length > 0) {
            $results['solution'] = trim(strip_tags($dom->saveHTML($resolution->item(0)), '<p><br><ul><li><ol><strong><em><a><table><tr><td><th><tbody><thead>'));
        }

        // Try to extract Response Matrix as software affected/solution combo
        $tables = $xpath->query('.//table', $node);
        if ($tables->length > 0) {
            // Keep the first table usually the response matrix
            $results['software_affected'] = "See Response Matrix in Description";
        }
    }

    return $results;
}

// Allow CLI execution only if directly called
if (php_sapi_name() === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    $result = fetch_vmware_advisories(false);
    print_r($result);
}

?>
