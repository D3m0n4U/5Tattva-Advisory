<?php
// scraper_microsoft.php
// Fetches latest advisories from Microsoft Security Response Center (MSRC)

require_once 'db.php';

function fetch_microsoft_advisories($silent = false)
{
    // Top 20 latest vulnerabilities
    $url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?\$orderby=releaseDate%20desc&\$top=20";

    if (!$silent)
        echo "Fetching Microsoft from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $json_content = @file_get_contents($url, false, $context);

    if ($json_content === false) {
        if (!$silent)
            echo "Failed to fetch Microsoft API.<br>";
        return ["status" => "error", "message" => "Failed to fetch Microsoft API"];
    }

    $data = json_decode($json_content, true);
    if (!isset($data['value']) || !is_array($data['value'])) {
        return ["status" => "error", "message" => "Invalid Microsoft JSON response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($data['value'] as $item) {
        $cve = $item['cveNumber'] ?? '';
        $title = $item['cveTitle'] ?? 'Microsoft Security Update';
        $release_date = $item['releaseDate'] ?? '';

        $issue_date = $release_date ? date('Y-m-d', strtotime($release_date)) : date('Y-m-d');

        // Determine severity
        $severity = 'Medium';
        if (isset($item['severity']) && !empty($item['severity'])) {
            $severity = $item['severity'];
        }
        elseif (isset($item['baseScore'])) {
            $score = floatval($item['baseScore']);
            if ($score >= 9.0)
                $severity = 'Critical';
            elseif ($score >= 7.0)
                $severity = 'High';
            elseif ($score >= 4.0)
                $severity = 'Medium';
            else
                $severity = 'Low';
        }

        $description = $item['unformattedDescription'] ?? '';

        // Fetch full rich data if we have a CVE
        $rich_description = '';
        if (!empty($cve)) {
            $detail_url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$cve";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $detail_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, "FiveTattva-Cyberhub-Integration/1.0");
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $detail_json = curl_exec($ch);
            curl_close($ch);

            if ($detail_json) {
                $detail_data = json_decode($detail_json, true);
                if ($detail_data) {
                    // Update exact severity / score if present in detail
                    if (isset($detail_data['severity']) && !empty($detail_data['severity'])) {
                        $severity = $detail_data['severity'];
                    }
                    if (isset($detail_data['baseScore'])) {
                        $score = floatval($detail_data['baseScore']);
                        if ($score >= 9.0)
                            $severity = 'Critical';
                        elseif ($score >= 7.0)
                            $severity = 'High';
                        elseif ($score >= 4.0)
                            $severity = 'Medium';
                        else
                            $severity = 'Low';
                    }

                    // 1. Executive Summary
                    $summary = $detail_data['unformattedDescription'] ?? '';
                    if (isset($detail_data['articles'])) {
                        foreach ($detail_data['articles'] as $article) {
                            if (isset($article['articleType']) && strtolower($article['articleType']) === 'executive summary' && !empty($article['description'])) {
                                $summary = $article['description'];
                            }
                        }
                    }
                    if (!empty($summary)) {
                        $rich_description .= "<h3>Executive Summary</h3>" . $summary;
                    }

                    // 2. Metrics 
                    if (isset($detail_data['baseScore']) && isset($detail_data['vectorString'])) {
                        $rich_description .= "<h3>Metrics</h3>";
                        $rich_description .= "<p><strong>Base Score:</strong> " . htmlspecialchars($detail_data['baseScore']) . " | <strong>Severity:</strong> " . htmlspecialchars($severity) . "</p>";
                        $rich_description .= "<p><strong>Vector:</strong> " . htmlspecialchars($detail_data['vectorString']) . "</p>";
                    }

                    // 3. FAQs / Mitigations / Workarounds
                    $sections = [
                        'faq' => 'FAQ',
                        'mitigation' => 'Mitigations',
                        'workaround' => 'Workarounds'
                    ];

                    foreach ($sections as $key => $heading) {
                        $html_block = "";
                        if (isset($detail_data['articles'])) {
                            foreach ($detail_data['articles'] as $article) {
                                if (isset($article['articleType']) && strtolower($article['articleType']) === $key && !empty($article['description'])) {
                                    $html_block .= $article['description'] . "<br><br>";
                                }
                            }
                        }
                        if (!empty($html_block)) {
                            $rich_description .= "<h3>$heading</h3>" . $html_block;
                        }
                    }

                    $rich_description = strip_tags($rich_description, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote><div><span>');
                }
            }
        }

        // Fallback
        if (empty($rich_description)) {
            if (empty($description) && isset($item['revisions'][0]['unformattedDescription'])) {
                $description = $item['revisions'][0]['unformattedDescription'];
            }
            if (empty($description)) {
                $description = "See Microsoft Security Update Guide for details.";
            }
            $rich_description = "<p>" . htmlspecialchars($description) . "</p>";
        }

        $link = "https://msrc.microsoft.com/update-guide/vulnerability/" . $cve;
        if (empty($cve)) {
            $cve = "MSRC-" . md5($title . $release_date);
            $link = "https://msrc.microsoft.com/update-guide/en-US";
        }

        // Construct standard data format
        $details = [
            ':source_id' => $cve,
            ':source' => 'Microsoft',
            ':title' => $title,
            ':severity' => ucfirst(strtolower($severity)),
            ':issue_date' => $issue_date,
            ':description' => $rich_description,
            ':software_affected' => $item['tag'] ?? 'Microsoft Products',
            ':solution' => 'Apply security updates as per MSRC guidance',
            ':original_link' => $link
        ];

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved Microsoft: $cve<br>\n";
        }
        else {
            if (!$silent)
                echo "Skipped Microsoft (Duplicate): $cve<br>\n";
        }

        $processed++;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

if (php_sapi_name() === 'cli') {
    $result = fetch_microsoft_advisories(false);
    print_r($result);
}
?>
