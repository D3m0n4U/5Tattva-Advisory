<?php
// scraper_linux.php
// Fetches latest security notices from Ubuntu USN RSS Feed

require_once 'db.php';

function fetch_linux_advisories($silent = false)
{
    // Ubuntu Security Notices RSS
    $url = "https://ubuntu.com/security/notices/rss.xml";

    if (!$silent)
        echo "Fetching Linux (USN) from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n"
        ]
    ]);

    $xml_content = @file_get_contents($url, false, $context);

    if ($xml_content === false) {
        if (!$silent)
            echo "Failed to fetch Linux (USN) RSS Feed.<br>";
        return ["status" => "error", "message" => "Failed to fetch Linux RSS"];
    }

    $xml = @simplexml_load_string($xml_content);
    if ($xml === false || !isset($xml->channel->item)) {
        return ["status" => "error", "message" => "Invalid Linux XML response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($xml->channel->item as $item) {
        $title = (string)$item->title;
        $link = (string)$item->link;
        $description_html = (string)$item->description;
        $pubDate = (string)$item->pubDate;

        $issue_date = date('Y-m-d', strtotime($pubDate));

        // Strip out HTML tags for a cleaner text description, but optionally we can keep it.
        $description = strip_tags($description_html);

        // Extract USN ID from title if possible (e.g., "USN-7301-1: Curl vulnerabilities")
        $pseudo_id = "USN-" . md5($link);
        if (preg_match('/USN-\d+-\d+/i', $title, $matches)) {
            $pseudo_id = $matches[0];
        }

        // Deduce severity - USN doesn't explicitly state CVSS in the RSS. 
        // We will default to High for USNs as they are patched vulnerabilities.
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

            // The main content is usually inside a <main> tag or under an h1 tag
            $h1s = $xpath->query('//h1');
            if ($h1s->length > 0) {
                $parent = $h1s->item(0)->parentNode;
                // Walk up until we find a reasonable container
                while ($parent && $parent->nodeName !== 'main' && strpos($parent->getAttribute('class'), 'inner-wrapper') === false && $parent->nodeName !== 'body') {
                    $parent = $parent->parentNode;
                }

                if ($parent) {
                    // Fix relative links
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

                    // Remove <nav>, <script>, <style> tags
                    $content_html = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', "", $content_html);
                    $content_html = preg_replace('/<style\b[^>]*>(.*?)<\/style>/is', "", $content_html);
                    $content_html = preg_replace('/<nav\b[^>]*>(.*?)<\/nav>/is', "", $content_html);
                    $content_html = preg_replace('/<ol[^>]*class="[^"]*breadcrumbs[^"]*"[^>]*>(.*?)<\/ol>/is', "", $content_html); // remove breadcrumbs
                    $content_html = str_replace("Open side navigation", "", $content_html); // remove weird nav text

                    // Remove redundant fields already displayed in global UI (Title and Publication Date)
                    $content_html = preg_replace('/<h1[^>]*>.*?<\/h1>/is', "", $content_html);

                    // Convert paragraph-based headings to actual HTML headings
                    $content_html = preg_replace('/<p[^>]*class="[^"]*p-heading--[1-6][^"]*"[^>]*>(.*?)<\/p>/is', "<h3>$1</h3>", $content_html);

                    // Remove Publication date header and the paragraph directly following it safely
                    $content_html = preg_replace('/<h3[^>]*>\s*Publication date\s*<\/h3>/is', "", $content_html);
                    $content_html = preg_replace('/<p[^>]*>\s*[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4}\s*<\/p>/is', "", $content_html);

                    // Remove contact team footer (which gets converted to h3 tags)
                    $content_html = preg_replace('/<h3[^>]*>\s*Have additional questions\?\s*<\/h3>\s*<h3[^>]*>.*?Talk to a member of the team.*?<\/h3>/is', "", $content_html);

                    // Remove JS toggle buttons ("Show X more references") and their associated truncated lists
                    $content_html = preg_replace('/<button[^>]*>.*?<\/button>/is', "", $content_html);
                    $content_html = preg_replace('/<ul[^>]*class="[^"]*truncated[^"]*"[^>]*>.*?<\/ul>/is', "", $content_html);

                    // Remove Ubuntu Pro promotional text
                    $content_html = preg_replace('/<[hH][1-6][^>]*>\s*Reduce your security exposure\.?\s*<\/[hH][1-6]>\s*<p[^>]*>.*?Ubuntu Pro provides ten-year security coverage.*?<\/p>\s*<p[^>]*>.*?Get Ubuntu Pro.*?<\/p>/is', "", $content_html);

                    // Strip unsafe/layout tags but retain formatting
                    $clean_html = strip_tags($content_html, '<h1><p><br><ul><li><ol><strong><em><a><h2><h3><h4><h5><h6><table><tr><td><th><tbody><thead><pre><code><blockquote>');

                    // Fallback to remove the text even if tag structure differs
                    $clean_html = preg_replace('/Reduce your security exposure.*?Get Ubuntu Pro/is', '', $clean_html);

                    // Clean up multiple spaces and empty lines slightly
                    $clean_html = preg_replace('/(\n\s*){3,}/', "\n\n", $clean_html);

                    if (!empty(trim($clean_html))) {
                        $description = trim($clean_html);
                    }
                }
            }
        }

        // Construct standard data format
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

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved Linux: $pseudo_id<br>\n";
        }
        else {
            if (!$silent)
                echo "Skipped Linux (Duplicate): $pseudo_id<br>\n";
        }

        $processed++;

        if ($processed >= 20)
            break; // Limit to 20
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

if (php_sapi_name() === 'cli') {
    $result = fetch_linux_advisories(false);
    print_r($result);
}
?>
