<?php
// scraper_nvd.php
// Fetches latest vulnerabilities from NVD (National Vulnerability Database)

require_once 'db.php';

function fetch_nvd_advisories($silent = false)
{
    // NVD API 2.0 Endpoint
    // We fetch the latest vulnerabilities. By default it returns 2000 results.
    // We'll limit it using pubStartDate to just get recent ones to avoid massive payloads.

    // Get date 2 days ago
    $start_date_utc = gmdate('Y-m-d\TH:i:s.000\Z', strtotime('-2 days'));
    $end_date_utc = gmdate('Y-m-d\TH:i:s.000\Z');

    // NVD recommends `lastModStartDate` to capture published OR recently analyzed vulnerabilities.
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=$start_date_utc&lastModEndDate=$end_date_utc";

    if (!$silent)
        echo "Fetching NVD from: $url\n<br>";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, "FiveTattva-Cyberhub-Integration/1.0");
    curl_setopt($ch, CURLOPT_TIMEOUT, 45); // NVD can be slow
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    $json = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err = curl_error($ch);
    curl_close($ch);

    if ($json === false || $http_code !== 200) {
        if (!$silent)
            echo "Failed to fetch NVD data (HTTP $http_code). Error: $curl_err<br>";
        return ["status" => "error", "message" => "Failed to fetch NVD API"];
    }

    $data = json_decode($json, true);
    if (!isset($data['vulnerabilities'])) {
        return ["status" => "error", "message" => "Invalid NVD JSON response"];
    }

    $vulnerabilities = $data['vulnerabilities'];
    $new_count = 0;
    $processed = 0;

    foreach ($vulnerabilities as $vuln_wrapper) {
        $cve = $vuln_wrapper['cve'];
        $cve_id = $cve['id'];

        // Description (English preferred)
        $description = '';
        foreach ($cve['descriptions'] as $desc) {
            if ($desc['lang'] === 'en') {
                $description = $desc['value'];
                break;
            }
        }

        // Severity (CVSS v3.1 preferred)
        $severity_label = 'Unknown';
        if (isset($cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'])) {
            $severity_label = ucfirst(strtolower($cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']));
        }
        elseif (isset($cve['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity'])) {
            $severity_label = ucfirst(strtolower($cve['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']));
        }
        elseif (isset($cve['metrics']['cvssMetricV2'][0]['baseSeverity'])) {
            $severity_label = ucfirst(strtolower($cve['metrics']['cvssMetricV2'][0]['baseSeverity']));
        }

        // Software Affected
        $software_affected_list = [];
        if (isset($cve['configurations'])) {
            foreach ($cve['configurations'] as $config) {
                if (isset($config['nodes'])) {
                    foreach ($config['nodes'] as $node) {
                        if (isset($node['cpeMatch'])) {
                            foreach ($node['cpeMatch'] as $match) {
                                if (isset($match['criteria'])) {
                                    // criteria format: cpe:2.3:a:vendor:product:version:...
                                    $parts = explode(':', $match['criteria']);
                                    if (count($parts) >= 5) {
                                        $vendor = $parts[3];
                                        $product = $parts[4];
                                        // Some cleaning for display
                                        $software = ucfirst(str_replace('_', ' ', $vendor)) . ' ' . ucfirst(str_replace('_', ' ', $product));

                                        if (isset($match['versionEndExcluding'])) {
                                            $software .= ' (< ' . $match['versionEndExcluding'] . ')';
                                        }
                                        elseif (isset($match['versionEndIncluding'])) {
                                            $software .= ' (<= ' . $match['versionEndIncluding'] . ')';
                                        }
                                        elseif (isset($parts[5]) && $parts[5] !== '*' && $parts[5] !== '-') {
                                            $software .= ' ' . $parts[5];
                                        }

                                        if (!in_array($software, $software_affected_list)) {
                                            $software_affected_list[] = $software;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        $software_affected = 'See description';
        if (!empty($software_affected_list)) {
            // Take top 5 to avoid massive lists
            $display_list = array_slice($software_affected_list, 0, 5);
            $software_affected = implode(', ', $display_list);
            if (count($software_affected_list) > 5) {
                $software_affected .= ' and ' . (count($software_affected_list) - 5) . ' more...';
            }
        }

        // Date
        $published = date('Y-m-d', strtotime($cve['published']));

        // Optional title logic from Weaknesses
        $title = $cve_id . ' Vulnerability';
        if (isset($cve['weaknesses'][0]['description'][0]['value'])) {
            $cwe = $cve['weaknesses'][0]['description'][0]['value'];
            if ($cwe !== 'NVD-CWE-noinfo' && $cwe !== 'NVD-CWE-Other') {
                $title = $cve_id . ' (' . $cwe . ')';
            }
        }

        // Fetch Full HTML from NVD for Rich Description
        $detail_url = "https://nvd.nist.gov/vuln/detail/$cve_id";
        $rich_description = '';

        $ch2 = curl_init();
        curl_setopt($ch2, CURLOPT_URL, $detail_url);
        curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch2, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_setopt($ch2, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch2, CURLOPT_SSL_VERIFYPEER, false);
        $html = curl_exec($ch2);
        curl_close($ch2);

        if ($html) {
            $dom = new DOMDocument();
            @$dom->loadHTML($html);
            $xpath = new DOMXPath($dom);

            $clean_html = "";

            // 1. Description Block
            $desc_nodes = $xpath->query('//p[@data-testid="vuln-description"]');
            if ($desc_nodes->length > 0) {
                $clean_html .= "<h3>Description</h3>" . $dom->saveHTML($desc_nodes->item(0));
            }
            else {
                // Fallback to API description
                $clean_html .= "<h3>Description</h3><p>" . htmlspecialchars($description) . "</p>";
            }

            // 2. Metrics (CVSS)
            $metrics = $xpath->query('//div[@id="vulnCvssPanel"]');
            if ($metrics->length > 0) {
                $clean_html .= "<h3>Metrics</h3>" . $dom->saveHTML($metrics->item(0));
            }

            // 3. Hyperlinks
            $links = $xpath->query('//table[@data-testid="vuln-hyperlinks-table"]');
            if ($links->length > 0) {
                $clean_html .= "<h3>References</h3>" . $dom->saveHTML($links->item(0));
            }

            // 4. Weaknesses
            $weakness = $xpath->query('//div[@id="vulnTechnicalDetailsPanel"]//table[contains(@data-testid, "vuln-CWEs")]');
            if ($weakness->length > 0) {
                $clean_html .= "<h3>Weaknesses</h3>" . $dom->saveHTML($weakness->item(0));
            }

            if (!empty($clean_html)) {
                $temp_dom = new DOMDocument();
                @$temp_dom->loadHTML('<?xml encoding="utf-8" ?><body>' . $clean_html . '</body>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
                $xpath2 = new DOMXPath($temp_dom);

                // Cleanup
                foreach ($xpath2->query('//script | //style | //nav') as $node) {
                    $node->parentNode->removeChild($node);
                }

                // Fix relative links
                $base_domain = 'https://nvd.nist.gov';
                foreach ($xpath2->query('//a') as $a) {
                    $href = $a->getAttribute('href');
                    if (!empty($href) && !preg_match('/^https?:\/\//i', $href) && strpos($href, '#') !== 0 && strpos($href, 'mailto:') !== 0) {
                        $new_href = strpos($href, '/') === 0 ? $base_domain . $href : $base_domain . '/' . ltrim($href, '/');
                        $a->setAttribute('href', $new_href);
                    }
                    $a->setAttribute('target', '_blank');
                }

                $body = $temp_dom->getElementsByTagName('body')->item(0);
                foreach ($body->childNodes as $child) {
                    $rich_description .= $temp_dom->saveHTML($child);
                }

                $rich_description = strip_tags($rich_description, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote><div><span>');
            }
        }

        if (empty($rich_description)) {
            $rich_description = '<p>' . htmlspecialchars($description) . '</p>';
        }

        // Construct standard data format
        $details = [
            ':source_id' => $cve_id,
            ':source' => 'NVD', // Must match one of our known sources
            ':title' => $title,
            ':severity' => $severity_label,
            ':issue_date' => $published,
            ':description' => $rich_description,
            ':software_affected' => $software_affected,
            ':solution' => 'Check vendor advisories',
            ':original_link' => "https://nvd.nist.gov/vuln/detail/$cve_id"
        ];

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved NVD: $cve_id<br>\n";
        }
        else {
            // Update NVD advisory if already exists, as it could be updated with a new CVSS or CPEs.
            // Our standard deduplication just ignores. We will let it skip for now unless the user wanted updates.
            if (!$silent)
                echo "Skipped NVD (Duplicate/Exists): $cve_id<br>\n";
        }

        $processed++;

        // Limit to 30 for script performance unless a webhook sets it differently
        if ($processed >= 30)
            break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

// Allow CLI execution for testing
if (php_sapi_name() === 'cli') {
    $result = fetch_nvd_advisories(false);
    print_r($result);
}
?>
