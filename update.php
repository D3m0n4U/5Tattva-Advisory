<?php
// update.php
// Triggers the scraper manually

set_time_limit(0); // Prevent fatal timeout error
ignore_user_abort(true); // Allow script to finish even if user closes the browser

require_once 'scraper_certin.php';
require_once 'scraper_nvd.php';
require_once 'scraper_cisa.php';
require_once 'scraper_github.php';
require_once 'scraper_microsoft.php';
require_once 'scraper_linux.php';


// Execute all scrapers
$results = [
    'certin' => fetch_certin_advisories(true),
    'nvd' => fetch_nvd_advisories(true),
    'cisa' => fetch_cisa_advisories(true),
    'github' => fetch_github_advisories(true),
    'microsoft' => fetch_microsoft_advisories(true),
    'linux' => fetch_linux_advisories(true)
];

// Calculate totals
$total_new = 0;
$total_processed = 0;

foreach ($results as $source => $res) {
    if (isset($res['new']))
        $total_new += $res['new'];
    if (isset($res['processed']))
        $total_processed += $res['processed'];
}

$final_result = [
    "status" => "success",
    "new" => $total_new,
    "processed" => $total_processed,
    "details" => $results
];

header('Content-Type: application/json');
echo json_encode($final_result);
?>
