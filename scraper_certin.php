<?php
// scraper_certin.php
// Five Tattva Cyberhub Security LLP
// Cert-IN Scraper

require_once 'db.php';

// Disable SSL verification for simplicity in local dev (Not recommended for prod)
$context = stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
    ],
    'http' => [
        'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n",
        'timeout' => 30 // Stop hanging after 30 seconds
    ]
]);

function fetch_certin_advisories($silent = false)
{
    global $context;
    $year = date('Y');
    $years_to_try = [$year, $year - 1]; // Try current, then previous year
    $html = false;

    foreach ($years_to_try as $y) {
        $list_url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST02&year=" . $y;
        if (!$silent)
            echo "Fetching list from: $list_url\n<br>";

        $html = @file_get_contents($list_url, false, $context);

        if ($html !== false) {
            break; // Success
        }
        else {
            if (!$silent)
                echo "Failed to fetch $y. Trying previous year...\n<br>";
        }
    }

    if (!$html) {
        return ["error" => "Failed to fetch list page (tried $year and " . ($year - 1) . ")"];
    }

    // DEMO FALLBACK: If content is too small (likely blocked), return Mock Data
    if (strlen($html) <= 2000) {
        if (!$silent)
            echo "<b>Notice:</b> Server is blocking requests (Anti-bot). Returning <b>Mock Data</b> for UI verification.<br>\n";

        // Mock Item mimicking a real scraped structure
        $mock_id = "CIAD-2026-0001";
        $mock_desc = '
<div class="content-wrapper">
    <h3>Executive Summary</h3>
    <p>This is a <b>Sample Advisory</b> generated because the Cert-In server is currently rate-limiting the scraper. Use this to verify the professional styling.</p>
    
    <table>
        <tr>
            <th>Parameter</th>
            <th>Details</th>
        </tr>
        <tr>
            <td><strong>Severity</strong></td>
            <td><strong>High</strong></td>
        </tr>
        <tr>
            <td><strong>Affected Software</strong></td>
            <td>
                <ul>
                    <li>Google Chrome prior to 120.0.0.1</li>
                    <li>Mozilla Firefox</li>
                    <li>Microsoft Edge</li>
                </ul>
            </td>
        </tr>
    </table>

    <h3>Technical Details</h3>
    <p>Multiple vulnerabilities have been reported in the software which could allow an attacker to <a href="#">bypass security restrictions</a>, execute arbitrary code, or cause denial of service conditions.</p>
    
    <p>The vulnerabilities exist due to:</p>
    <ul>
        <li>Improper input validation in the rendering engine.</li>
        <li>Heap buffer overflow in the audio component.</li>
    </ul>

    <h3>Solution</h3>
    <p>Apply the appropriate updates as mentioned in the vendor advisory.</p>
</div>';

        $mock_item = [
            ':source_id' => $mock_id,
            ':source' => 'Cert-In',
            ':title' => 'Multiple Vulnerabilities in Google Chrome (Sample)',
            ':severity' => 'High',
            ':issue_date' => date('Y-m-d'),
            ':description' => $mock_desc,
            ':original_link' => 'https://www.cert-in.org.in/',
            ':software_affected' => 'Google Chrome, Firefox',
            ':solution' => 'Update to latest version'
        ];

        // $saved = save_advisory($mock_item); // Disabled per user request

        // Return success but don't count it as saved/new so it doesn't trigger UI refresh unless logic changes
        // Actually, if we return it here, the update.php will send it back as JSON.
        // But if it's not in DB, performSearch() won't find it.
        // So effectively this hides it.
        return [
            "status" => "success",
            "new" => 0,
            "processed" => 1,
            "message" => "Server blocked. Returning Mock Data (Not Saved)."
        ];
    }

    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    $xpath = new DOMXPath($dom);

    // Find links that contain 'CIAD' (Cert-IN Advisory)
    // The structure is usually within a table
    $links = $xpath->query("//a[contains(@href, 'CIAD')]");

    $new_count = 0;
    $processed = 0;

    foreach ($links as $link) {
        $href = $link->getAttribute('href');
        $text = trim($link->nodeValue);

        // Extract ID from Text or Href
        // Href format: s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2025-0055
        preg_match('/VLCODE=(CIAD-\d{4}-\d{4})/', $href, $matches);

        if (isset($matches[1])) {
            $certin_id = $matches[1];
            $detail_url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=" . $certin_id;

            if (!$silent)
                echo "Processing: $certin_id ... ";
            $details = fetch_advisory_details($detail_url, $certin_id, $text, $silent);

            if ($details) {
                $saved = save_advisory($details);
                if ($saved) {
                    $new_count++;
                    if (!$silent)
                        echo "Saved.<br>\n";
                }
                else {
                    if (!$silent)
                        echo "Skipped (Duplicate).<br>\n";
                }
            }
            else {
                if (!$silent)
                    echo "<b>Skipped (Content Invalid/404).</b><br>\n";
            // Optionally track skip count if needed in return
            }
            $processed++;
        // Be nice to the server
        // usleep(500000); // 0.5s delay
        }

        // Limit for testing to avoid scraping everything at once if there are hundreds
        if ($processed >= 5)
            break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

function fetch_advisory_details($url, $id, $list_title, $silent = false)
{
    global $context;
    $html = @file_get_contents($url, false, $context);

    // Basic HTTP check failure
    if (!$html || strlen($html) < 200) {
        if (!$silent)
            echo "[Error: HTML too short or empty] ";
        return null;
    }

    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    $xpath = new DOMXPath($dom);

    // Extraction Logic based on typical Cert-IN structure
    // They often use <font color="#990000"><b>CIAD-XXXX-XXXX</b></font> as header
    // And then a table for content.

    // Attempt to grab the main title (Subject)
    // Structure observed: inside a specific table structure

    // We will dump the whole body text or main table text into 'description' 
    // and try to parse specific fields if possible.

    $clean_text = ""; // not used currently

    // ---------------------------------------------------------
    // VALIDATION: Check for "Page Not Found" or generic error pages before proceeding
    // ---------------------------------------------------------
    $page_text = $dom->textContent;
    if (stripos($page_text, 'Page Not Found') !== false || stripos($page_text, 'HTTP 404') !== false) {
        if (!$silent)
            echo "[Error: 404 Detected] ";
        return null;
    }

    if (strlen(trim($page_text)) < 50) {
        if (!$silent)
            echo "[Error: Page content practically empty] ";
        return null;
    }

    // ---------------------------------------------------------
    // TITLE EXTRACTION: Initial Default
    // ---------------------------------------------------------
    $title = $list_title; // Default to the list title


    // ---------------------------------------------------------
    // CONTENT EXTRACTION (Moved BEFORE Images)
    // ---------------------------------------------------------

    // Improve Table Detection: Find ALL tables with "Software Affected" and pick the smallest one
    // to avoid selecting the main layout table.
    $tables = $dom->getElementsByTagName('table');
    $candidates = [];
    foreach ($tables as $table) {
        if (stripos($table->nodeValue, 'Software Affected') !== false) {
            $candidates[] = $table;
        }
    }

    $main_table = null;
    if (!empty($candidates)) {
        // Sort by length of text content ASC
        usort($candidates, function ($a, $b) {
            return strlen($a->nodeValue) - strlen($b->nodeValue);
        });
        $main_table = $candidates[0];
    }

    $severity = "Unknown";
    $description = "";
    $software_affected = "";
    $solution = "";
    // Title is already handled above or defaults to list_title

    $content_node = null;

    if ($main_table) {
        // Cleaning: Remove scripts, styles, forms, and headers from the detected table to prevent visual bugs
        $removals = [];
        foreach ($main_table->getElementsByTagName('script') as $node)
            $removals[] = $node;
        foreach ($main_table->getElementsByTagName('style') as $node)
            $removals[] = $node;
        foreach ($main_table->getElementsByTagName('link') as $node)
            $removals[] = $node;

        foreach ($removals as $node) {
            $node->parentNode->removeChild($node);
        }

        // Refinement: Extract ONLY the content cell/part, not the whole table if it contains a sidebar
        // The Cert-In site often has a structure like <tr><td class="left_panel">...</td><td class="content">...</td></tr>
        // We want to extract the logical content container.

        // Try to find a cell with "Software Affected" inside the main table
        $content_node = $main_table;
        $cells = $main_table->getElementsByTagName('td');

        // Filter out sidebar cells explicitly if they contain "Home" or "Constituencies" or "News"
        $real_content_found = false;

        foreach ($cells as $cell) {
            $cellText = $cell->nodeValue;
            // Heuristic: Sidebar usually has list of links like "Home", "About Us", "Advisories"
            if (stripos($cellText, 'Constituencies') !== false && stripos($cellText, 'About Us') !== false) {
                continue; // Skip sidebar
            }

            if (stripos($cellText, 'Software Affected') !== false) {
                // Check if this cell is "too small" (just a header) or the actual content container
                if (strlen($cellText) > 200) {
                    $content_node = $cell;
                    $real_content_found = true;
                    break;
                }
            }
        }

        // If we didn't find a specific separate cell, maybe the sidebar is a sibling of the main table in a parent table?
        // But if we selected the "smallest table with Software Affected", we hopefully avoided the wrapper.
        // Just in case, let's aggressively remove any node that looks like the contact info footer.

        // Remove presentational attributes
        $xpath_clean = new DOMXPath($dom);
        $all_nodes = $xpath_clean->query('.//*', $content_node);
        foreach ($all_nodes as $node) {
            $node->removeAttribute('width');
            $node->removeAttribute('height');
            $node->removeAttribute('bgcolor');
            $node->removeAttribute('align');
            $node->removeAttribute('style');
            $node->removeAttribute('border');
            $node->removeAttribute('cellpadding');
            $node->removeAttribute('cellspacing');
        }

    }
    else {
        // Fallback: body (cleaned)
        $body = $dom->getElementsByTagName('body')->item(0);
        if ($body) {
            $removals = [];
            foreach ($body->getElementsByTagName('script') as $node)
                $removals[] = $node;
            foreach ($body->getElementsByTagName('style') as $node)
                $removals[] = $node;
            foreach ($body->getElementsByTagName('header') as $node)
                $removals[] = $node;
            foreach ($body->getElementsByTagName('footer') as $node)
                $removals[] = $node;

            foreach ($removals as $node) {
                $node->parentNode->removeChild($node);
            }

            // Unwrap Forms (preserve content)
            $forms = [];
            foreach ($body->getElementsByTagName('form') as $node)
                $forms[] = $node;
            foreach ($forms as $form) {
                while ($form->firstChild) {
                    $form->parentNode->insertBefore($form->firstChild, $form);
                }
                $form->parentNode->removeChild($form);
            }

            $content_node = $body;
        }
    }

    if (!$content_node)
        return null; // Should not happen given validation

    // Save initial description for Metadata Processing
    $description_for_meta = "";
    if ($content_node instanceof DOMDocument) {
        foreach ($content_node->childNodes as $child)
            $description_for_meta .= $dom->saveHTML($child);
    }
    else {
        $description_for_meta = $dom->saveHTML($content_node);
    }

    // ---------------------------------------------------------
    // METADATA & TITLE EXTRACTION (Scoped to Content)
    // ---------------------------------------------------------

    // Normalize ONLY the content description for regex/search
    $normalized_desc = preg_replace('/\s+/', ' ', $description_for_meta);
    $normalized_desc = str_replace('&nbsp;', ' ', $normalized_desc);
    $normalized_desc = preg_replace('/\xc2\xa0/', ' ', $normalized_desc);
    $plain_text_desc = strip_tags($description_for_meta);

    // A. Title Extraction from Content
    // Try "Subject:" regex first in the content
    if (preg_match('/Subject\s*:\s*(.*?)(<br|<\/p)/i', $description_for_meta, $matches)) {
        $t = trim(strip_tags($matches[1]));
        if (strlen($t) > 5) {
            $title = $t;
            if (!$silent)
                echo " [Found Title (Subject/Content): " . substr($title, 0, 30) . "...] ";
        }
    }

    // Fallback: Bold Heuristics within content node
    if ($title == $list_title || strpos($title, 'CIAD-') !== false) {
        if ($content_node) {
            $bolds = $content_node->getElementsByTagName('b');
            foreach ($bolds as $b) {
                $t = trim($b->textContent);
                if (strlen($t) > 15 &&
                strpos($t, 'CIAD-') === false &&
                stripos($t, 'Severity') === false &&
                stripos($t, 'Software') === false &&
                stripos($t, 'Description') === false &&
                stripos($t, 'Solution') === false &&
                stripos($t, 'Directions') === false &&
                stripos($t, 'Guidelines') === false
                ) {
                    $title = $t;
                    if (!$silent)
                        echo " [Found Title (Bold/Content): " . substr($title, 0, 30) . "...] ";
                    break;
                }
            }
        }
    }

    // B. Metadata Extraction (Severity / Date)
    $severity = "Unknown";
    $issue_date = date('Y-m-d');

    // Severity
    if (preg_match('/Severity Rating:\s*([A-Za-z]+)/i', $normalized_desc, $matches)) {
        $severity = trim($matches[1]);
    }
    else {
    // Fallback XPath on content node would be complex, rely on regex for normalized content
    }

    // Date
    if (preg_match('/Original Issue Date:\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})/i', $normalized_desc, $matches)) {
        $date_str = trim($matches[1]);
        $parsed_time = strtotime($date_str);
        if ($parsed_time) {
            $issue_date = date('Y-m-d', $parsed_time);
            if (!$silent)
                echo " [Date: $issue_date] ";
        }
    }

    // ---------------------------------------------------------
    // IMAGE OPTIMIZATION: Only download images INSIDE $content_node
    // ---------------------------------------------------------

    $imgs = $content_node->getElementsByTagName('img');
    // Note: getElementsByTagName returns a live list. If we modify (e.g. remove), it changes.
    // So we iterate backwards or convert to array.
    $img_list = [];
    foreach ($imgs as $img)
        $img_list[] = $img;

    foreach ($img_list as $img) {
        $src = $img->getAttribute('src');

        // Filter 1: Skip based on extension/name (GIFs, spacers)
        if (stripos($src, '.gif') !== false || stripos($src, 'spacer') !== false || stripos($src, 'shim') !== false) {
            $img->parentNode->removeChild($img); // Remove junk image from DOM
            continue;
        }

        // Filter 1.5: Blacklist specific junk images (Sidebar/Footer logos)
        $junk_keywords = [
            'Digital_India', 'csk_', 'firstlogo', 'apcert', 'tfCsirt', 'banner', 'Charter', 'CNA',
            'igov', 'pubport', 'mygov', 'isac', 'NVSP', 'modeofPayment', 'digital-payment',
            'RTI', 'Collaboration', 'CSIRT', 'RECRUITEMENTS', 'security_brochures', 'youtube',
            'facebook', 'twitter', 'linkedin', 'insta', 'vigilance', 'g20', 'twit', 'Link',
            'cert_in', 'testprin', 'shim', 'spacer', 'arrow', 'bullet', 'icon', 'logo'
        ];

        $is_junk = false;
        foreach ($junk_keywords as $kw) {
            if (stripos($src, $kw) !== false) {
                $is_junk = true;
                break;
            }
        }

        if ($is_junk) {
            $img->parentNode->removeChild($img);
            continue;
        }

        // Skip if empty or data URI
        if (!$src || strpos($src, 'data:') === 0)
            continue;

        // Resolve absolute URL
        $abs_url = $src;
        if (!preg_match('/^https?:\/\//', $src)) {
            // Handle relative paths correctly
            if (strpos($src, '/') === 0) {
                // Root relative
                $abs_url = 'https://www.cert-in.org.in' . $src;
            }
            else {
                // Document relative
                $abs_url = 'https://www.cert-in.org.in/' . $src;
            }
        }

        // Generate local filename
        $ext = pathinfo(parse_url($abs_url, PHP_URL_PATH), PATHINFO_EXTENSION);
        if (!$ext)
            $ext = 'jpg';
        $safe_id = preg_replace('/[^a-zA-Z0-9-]/', '_', $id);
        $filename = "{$safe_id}_" . md5($abs_url) . ".$ext";
        $local_path = __DIR__ . "/images/$filename";
        $web_path = "images/$filename";

        // Check if we should download
        $should_download = false;
        if (file_exists($local_path)) {
            $should_download = false; // Already have it
        }
        else {
            $should_download = true;
        }

        if ($should_download) {
            // Add Referer to context
            $image_context = stream_context_create([
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
                'http' => [
                    'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n" .
                    "Referer: $url\r\n"
                ]
            ]);

            // Filter 2: HEAD request or download and check size?
            // Since we want to check size, let's download to temp var
            $image_data = @file_get_contents($abs_url, false, $image_context);

            // Filter 3: Minimum Size (e.g. 3KB) to avoid icons/bullets that aren't content
            if ($image_data && strlen($image_data) > 3000) {
                file_put_contents($local_path, $image_data);
                if (!$silent)
                    echo " [Img: OK] ";
            }
            else {
                // Too small or failed. 
                // If too small, maybe we should remove it from DOM too to keep it clean?
                // Or just leave it broken/linked to remote?
                // User asked to "remove all the images etc that are not req".
                // Let's remove it from DOM if we decided not to keep it.
                $img->parentNode->removeChild($img);
                continue; // Skip setting src
            }
        }
        else {
        // we have it locally, ensure size check was passed (roughly) - assumed yes if exists
        }

        // Update src to local path (or fallback absolute)
        $img->setAttribute('src', $web_path);
        // Ensure responsive
        $img->setAttribute('style', 'max-width: 100%; height: auto;');
    }

    // FIX A TAG HREFS
    $a_links = $content_node->getElementsByTagName('a');
    $base_domain = 'https://www.cert-in.org.in';
    $a_list = [];
    foreach ($a_links as $a)
        $a_list[] = $a;

    foreach ($a_list as $a) {
        $href = $a->getAttribute('href');
        if (!empty($href) && !preg_match('/^https?:\/\//i', $href) && strpos($href, '#') !== 0 && strpos($href, 'mailto:') !== 0 && strpos($href, 'javascript:') !== 0) {
            $new_href = strpos($href, '/') === 0 ? $base_domain . $href : $base_domain . '/' . ltrim($href, '/');
            $a->setAttribute('href', $new_href);
        }
    }

    // Save HTML
    $description = "";
    if ($content_node instanceof DOMDocument || $content_node instanceof DOMElement) {
        foreach ($content_node->childNodes as $child) {
            $description .= $dom->saveHTML($child);
        }
    }
    else {
        $description = $dom->saveHTML($content_node);
    }

    // FINAL CLEANING: Remove "Contact Information" block and other footers
    // This is often at the end. We'll use regex to strip it.

    $patterns_to_remove = [
        '/<table[^>]*>.*?Contact Information.*?<\/table>/is', // Contact Info Table
        '/Contact Information.*?Email:.*?info@cert-in\.org\.in.*?Phone:.*?Postal address.*?India/is', // Contact Text block
        '/Postal address.*?Indian Computer Emergency Response Team.*?India/is', // Address Text block
        '/<td[^>]*class="pFooter"[^>]*>.*?<\/td>/is', // Generic Footer Cell
        '/Indian Computer Emergency Response Team - CERT-In.*?Government of India\./is', // Footer Text
        '/Website Policies.*?Terms of Use.*?Help/is', // Footer Links
        '/Help\s*Last\s*Updated\s*On.*?\d{4}/is', // "Help Last Updated On..." footer
        '/Last\s*Updated\s*On\s*January\s*09,\s*2026/is', // Specific date format observed
        '/Ministry\s*of\s*Electronics\s*and\s*Information\s*Technology.*?Government\s*of\s*India/is', // Ministry Header
        '/Electronics\s*Niketan.*?New\s*Delhi.*?India/is', // specific address block
        '/(Indian|n)?\s*Computer\s*Emergency\s*Response\s*Team\s*\(CERT-In\)/is', // Name artifact

        // Specific Junk found in inspection
        '/<span[^>]*>\s*(<br\s*\/?>\s*)+<\/p>/is', // Weird span-br-p combo
        '/<h2[^>]*>\s*(&nbsp;|\s)*<\/h2>/is', // Empty h2

        // Remove Digital India and Membership Logos/Badges
        '/Digital\s*India\s*Power\s*To\s*Empower/is',
        '/Full\s*Member/is',
        '/Operational\s*Member/is',
        '/Accredited\s*Member/is',
        '/CCKRA/is', // Common certification keyword often found nearby
        '/<img[^>]*Digital\s*India[^>]*>/is', // Specific image tags if alt text matches (though scraping might not have alt)
        '/<div[^>]*class="[^"]*(member|logo)[^"]*"[^>]*>.*?<\/div>/is', // Catch generic logo containers if classes match

    ];

    foreach ($patterns_to_remove as $pattern) {
        $description = preg_replace($pattern, '', $description);
    }

    // Also remove generic sidebar if it leaked in
    $description = preg_replace('/<td[^>]*>.*?Home.*?About Us.*?Constituencies.*?<\/td>/is', '', $description);

    // Robust DOM-based Cleanup following V3 logic
    $temp_dom = new DOMDocument();
    // Use hacks for HTML5 fragment
    @$temp_dom->loadHTML('<?xml encoding="utf-8" ?><body>' . $description . '</body>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    $temp_body = $temp_dom->getElementsByTagName('body')->item(0);

    // Normalize properties to headers
    normalize_dom_structure($temp_body, $temp_dom);

    clean_dom_containers($temp_body);

    // Remove trailing BRs/Whitespace from body root
    while ($temp_body->hasChildNodes()) {
        $last = $temp_body->lastChild;
        $remove = false;

        if ($last->nodeType === XML_TEXT_NODE) {
            $text = str_replace(["\xc2\xa0", "&nbsp;"], ' ', $last->nodeValue);
            if (trim($text) === '')
                $remove = true;
        }
        elseif ($last->nodeType === XML_ELEMENT_NODE) {
            if (strtolower($last->tagName) === 'br')
                $remove = true;
        }

        if ($remove) {
            $temp_body->removeChild($last);
        }
        else {
            break;
        }
    }

    $description = "";
    foreach ($temp_body->childNodes as $child) {
        $description .= $temp_dom->saveHTML($child);
    }
    $description = trim($description);


    // ---------------------------------------------------------
    // STRICT VALIDATION: Check real content length
    // ---------------------------------------------------------
    $text_content = trim(strip_tags($description));
    // Remove invisible chars/spaces
    $text_content = preg_replace('/\s+/', ' ', $text_content);

    if (strlen($text_content) < 100) {
        if (!$silent)
            echo " [Error: Content too short after cleaning (" . strlen($text_content) . " chars)] ";
        return null; // Reject this advisory
    }

    return [
        ':source_id' => $id,
        ':source' => 'Cert-In',
        ':title' => $title,
        ':severity' => $severity,
        ':issue_date' => $issue_date,
        ':description' => $description, // Storing full HTML for display fidelity
        ':software_affected' => '', // Hard to parse reliably, part of description
        ':solution' => '', // Hard to parse reliably, part of description
        ':original_link' => $url
    ];
}

function clean_dom_containers($node)
{
    if (!$node->hasChildNodes())
        return;

    // Iterate backwards
    for ($i = $node->childNodes->length - 1; $i >= 0; $i--) {
        $child = $node->childNodes->item($i);

        if ($child->nodeType === XML_ELEMENT_NODE) {
            // Recursively clean children first
            clean_dom_containers($child);

            $tag = strtolower($child->tagName);
            $containers = ['div', 'span', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'td', 'tr', 'table', 'section', 'article', 'aside', 'footer', 'header', 'nav', 'ul', 'ol', 'li'];

            if (in_array($tag, $containers)) {
                if (is_container_empty($child)) {
                    $node->removeChild($child);
                }
            }
        }
    }
}

function is_container_empty($node)
{
    if (!$node->hasChildNodes())
        return true;

    foreach ($node->childNodes as $child) {
        if ($child->nodeType === XML_TEXT_NODE) {
            $text = str_replace(["\xc2\xa0", "&nbsp;"], ' ', $child->nodeValue);
            if (trim($text) !== '')
                return false;
        }
        elseif ($child->nodeType === XML_ELEMENT_NODE) {
            $tag = strtolower($child->tagName);
            if (in_array($tag, ['img', 'input', 'hr', 'iframe', 'embed', 'object', 'video', 'audio', 'a']))
                return false;
            // If it's a 'br', we consider it empty content FOR A CONTAINER.
            if ($tag === 'br')
                continue;

            // If it is another container, check if it is empty (should have been removed by recursion, but double check)
            if (!is_container_empty($child))
                return false;
        }
    }
    return true;
}

function normalize_dom_structure($node, $dom)
{
    if (!$node->hasChildNodes())
        return;

    // Convert NodeList to array to modify DOM while iterating
    $children = iterator_to_array($node->childNodes);

    foreach ($children as $child) {
        if ($child->nodeType === XML_ELEMENT_NODE) {
            $tag = strtolower($child->tagName);
            $class = $child->getAttribute('class');

            // 1. Detect "verblue" headers and convert to H3
            // Case A: <p class="...verblue...">Header</p>
            // Case B: <span class="...verblue...">Header</span> nested or as block
            // Case A: <p class="...verblue...">Header</p>
            // Case B: <span class="...verblue...">Header</span> nested or as block
            if (stripos($class, 'verblue') !== false || stripos($class, 'subhead') !== false) {
                // SKIP if parent is an <a> tag (Link text should not be a header)
                if ($child->parentNode && strtolower($child->parentNode->tagName) === 'a') {
                    continue;
                }

                $text_content = trim($child->textContent);
                $text_len = strlen($text_content);

                // SKIP candidates for H3 if they look like URL, CVE ID, or specific labels
                $is_candidate = true;
                if (preg_match('/^https?:\/\//i', $text_content))
                    $is_candidate = false;
                if (preg_match('/^CVE-\d{4}-\d+/i', $text_content))
                    $is_candidate = false;
                // Demote specific labels to STRONG
                if (preg_match('/^(CVE Name|CVE ID|CVEs|Reference|Source|Credit)$/i', $text_content))
                    $is_candidate = false;

                // Also must be short
                if ($text_len > 100)
                    $is_candidate = false;

                if ($is_candidate && $text_len > 0) {
                    // Convert to H3
                    $new_node = $dom->createElement('h3', htmlspecialchars($child->textContent));
                    $node->replaceChild($new_node, $child);
                }
                else {
                    // It's not a header candidate.
                    // But it has 'verblue' class which causes unwanted styling (large font).
                    // We should STRIP the class so it renders normally (bold if <strong> is present, else normal).
                    // Exception: If it matched the "Demote" labels, we should wrap in strong if not already?
                    // The Fortinet case has <strong><b>CVE Name</b>... so it is already bold.
                    // Just stripping class is sufficient.
                    $child->removeAttribute('class');
                }
                continue;
            }

            // 2. Unwrap specific spans that just wrap other block elements or are redundant
            // e.g. <span class="contentTD"><p>...</p></span> -> <p>...</p>
            // Only if it has block children?
            if ($tag === 'span' && stripos($class, 'contentTD') !== false) {
                // Check if it contains block elements (p, ul, table, div)
                $has_block = false;
                foreach ($child->childNodes as $grandchild) {
                    if ($grandchild->nodeType === XML_ELEMENT_NODE &&
                    in_array(strtolower($grandchild->tagName), ['p', 'div', 'ul', 'ol', 'table', 'h1', 'h2', 'h3'])) {
                        $has_block = true;
                        break;
                    }
                }

                if ($has_block) {
                    // Unwrap
                    $fragment = $dom->createDocumentFragment();
                    while ($child->firstChild) {
                        $fragment->appendChild($child->firstChild);
                    }
                    $node->replaceChild($fragment, $child);
                // We just replaced 'child' with its children. 
                // We should probably recurse into the new children? 
                // The simple recursion below handles current child's *original* children which are now *current node's* children.
                // But the iterator `children` is stale.
                // It's acceptable to miss one pass of deep normalization for unwrapped content if we run this recursively? 
                // Actually `normalize_dom_structure` calls itself.
                // But we modified the tree. 
                // Let's just continue, the cleaning pass acts as a second filter or we can depend on next scrape.
                // For better robustness: Call normalize on the parent again? No, infinite loop risk.
                }
            }

            // Recurse
            normalize_dom_structure($child, $dom);
        }
    }
}
?>
