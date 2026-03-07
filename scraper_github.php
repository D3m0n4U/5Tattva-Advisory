<?php
// scraper_github.php
// Fetches latest advisories from GitHub Advisory Database

require_once 'db.php';

function parse_markdown($text)
{
    if (!$text)
        return '';

    // Escape HTML first to prevent XSS
    $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');

    $rules = [
        '/^######\s+(.*)$/m' => '<h6>$1</h6>',
        '/^#####\s+(.*)$/m' => '<h5>$1</h5>',
        '/^####\s+(.*)$/m' => '<h4>$1</h4>',
        '/^###\s+(.*)$/m' => '<h3>$1</h3>',
        '/^##\s+(.*)$/m' => '<h2>$1</h2>',
        '/^#\s+(.*)$/m' => '<h1>$1</h1>',
        '/\*\*(.*?)\*\*/s' => '<strong>$1</strong>',
        '/\*(.*?)\*/s' => '<em>$1</em>',
        '/\[([^\]]+)\]\(([^)]+)\)/' => '<a href="$2" target="_blank">$1</a>',
        '/```(.*?)```/s' => '<pre><code>$1</code></pre>',
        '/`(.*?)`/s' => '<code>$1</code>',
        '/^\s*[:-]\s+(.*)$/m' => '<li>$1</li>'
    ];

    foreach ($rules as $pattern => $replacement) {
        if ($pattern === '/\[([^\]]+)\]\(([^)]+)\)/')
            continue;
        $text = preg_replace($pattern, $replacement, $text);
    }

    // Handle links to fix relative URLs
    $text = preg_replace_callback('/\[([^\]]+)\]\(([^)]+)\)/', function ($m) {
        $href = $m[2];
        if (!empty($href) && !preg_match('/^https?:\/\//i', $href) && strpos($href, '#') !== 0 && strpos($href, 'mailto:') !== 0 && strpos($href, 'javascript:') !== 0) {
            $href = strpos($href, '/') === 0 ? 'https://github.com' . $href : 'https://github.com/' . ltrim($href, '/');
        }
        return '<a href="' . $href . '" target="_blank">' . $m[1] . '</a>';
    }, $text);

    // Wrap consecutive list items in <ul>
    $text = preg_replace('/(<li>.*<\/li>(\r?\n)*)+/s', "<ul>\n$0\n</ul>", $text);

    // Convert newlines to <br>
    $text = nl2br($text);

    // Clean up <br> tags inside <ul> and <pre>
    $text = preg_replace_callback('/<ul>(.*?)<\/ul>/s', function ($m) {
        return '<ul>' . preg_replace('/<br\s*\/?>/i', '', $m[1]) . '</ul>';
    }, $text);

    $text = preg_replace_callback('/<pre><code>(.*?)<\/code><\/pre>/s', function ($m) {
        return '<pre><code>' . preg_replace('/<br\s*\/?>/i', '', $m[1]) . '</code></pre>';
    }, $text);

    return $text;
}

function fetch_github_advisories($silent = false)
{
    // GitHub provides a public GraphQL API for the advisory database, but REST is simpler for anonymous requests
    // We can use the REST API to list repository advisories, however for global database we use GraphQL usually.
    // For simplicity without requiring auth, there exists an OSV (Open Source Vulnerability) mirror of GitHub Advisories
    // https://osv.dev/ API is unauthenticated and covers GitHub (GHSA).

    // Using OSV API to query recent GHSA (GitHub Security Advisories)
    // We'll query recent vulnerabilities and filter for GHSA

    // Payload for OSV query (simplest approach is fetching recent via ecosystem or modified time)
    // OSV doesn't have a simple "give me the last 50", but we can query by Ecosystem or use the NVD mirror.
    // However, a better approach for GHSA specifically without auth might be scraping or relying on a feed if OSV isn't direct.

    // Instead, let's use the public GitHub REST API for a specific ecosystem if we can't do global easily,
    // OR we use the NVD script which already includes GHSA if they have CVEs assigned.
    // But to fulfill the "integration" request explicitly for GitHub:
    $url = "https://api.github.com/advisories";

    if (!$silent)
        echo "Fetching GitHub Advisories from: $url\n<br>";

    $context = stream_context_create([
        'http' => [
            'header' => "User-Agent: FiveTattva-Cyberhub-Integration/1.0\r\n" .
            "Accept: application/vnd.github.v3+json\r\n"
        ]
    ]);

    $json = @file_get_contents($url, false, $context);

    if ($json === false) {
        if (!$silent)
            echo "Failed to fetch GitHub API (Rate limited or requires auth).<br>";
        return ["status" => "error", "message" => "Failed to fetch GitHub API"];
    }

    $advisories = json_decode($json, true);
    if (!is_array($advisories)) {
        return ["status" => "error", "message" => "Invalid GitHub JSON response"];
    }

    $new_count = 0;
    $processed = 0;

    foreach ($advisories as $adv) {
        $ghsa_id = $adv['ghsa_id'];
        $cve_id = $adv['cve_id'] ?? '';

        $cve_string = $ghsa_id;
        if (!empty($cve_id)) {
            $cve_string = $cve_id . ',' . $ghsa_id; // Pass both so Deduplication catches either
        }

        // Description
        $description = $adv['description'] ?? $adv['summary'] ?? 'No description provided.';

        // Severity
        $severity = ucfirst(strtolower($adv['severity'] ?? 'Unknown'));

        // Date
        $published = date('Y-m-d', strtotime($adv['published_at']));

        // Construct standard data format
        $details = [
            ':source_id' => $ghsa_id,
            ':source' => 'GitHub',
            ':title' => $adv['summary'] ?? 'GitHub Security Advisory: ' . $ghsa_id,
            ':severity' => $severity,
            ':issue_date' => $published,
            ':description' => parse_markdown($description),
            ':software_affected' => 'Open Source Ecosystem',
            ':solution' => 'Check repository for patched versions.',
            ':original_link' => $adv['html_url']
        ];

        // Inject CVEs manually to ensure our Deduplication logic catches it
        // The save_advisory function will extract CVEs from description, but GHSA might only have them in metadata
        $details[':cve_ids'] = $cve_string;

        $saved = save_advisory($details);
        if ($saved) {
            $new_count++;
            if (!$silent)
                echo "Saved GitHub: $ghsa_id<br>\n";
        }
        else {
            if (!$silent)
                echo "Skipped GitHub (Duplicate): $ghsa_id<br>\n";
        }

        $processed++;

        if ($processed >= 20)
            break;
    }

    return ["status" => "success", "new" => $new_count, "processed" => $processed];
}

if (php_sapi_name() === 'cli') {
    $result = fetch_github_advisories(false);
    print_r($result);
}
?>
