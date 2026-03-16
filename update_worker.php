<?php
// update_worker.php
// Background worker for scraping and syncing data

set_time_limit(0);
ignore_user_abort(true);

$status_file = __DIR__ . '/update_status.json';

function update_status($data) {
    global $status_file;
    file_put_contents($status_file, json_encode($data));
}

// 1. Mark as running
update_status([
    "status" => "running",
    "percent" => 0,
    "message" => "Initializing staging database...",
    "started_at" => date('Y-m-d H:i:s')
]);

require_once 'db.php';

$prod_db = __DIR__ . '/database.sqlite';
$staging_db = __DIR__ . '/staging.sqlite';

try {
    if (file_exists($prod_db)) {
        copy($prod_db, $staging_db);
    }

    init_db($staging_db);

    require_once 'scraper_certin.php';
    require_once 'scraper_nvd.php';
    require_once 'scraper_cisa.php';
    require_once 'scraper_github.php';
    require_once 'scraper_microsoft.php';
    require_once 'scraper_linux.php';
    require_once 'scraper_vmware.php';
    require_once 'scraper_oracle.php';
    require_once 'scraper_qualys.php';

    $scrapers = [
        'certin' => 'fetch_certin_advisories',
        'nvd' => 'fetch_nvd_advisories',
        'cisa' => 'fetch_cisa_advisories',
        'github' => 'fetch_github_advisories',
        'microsoft' => 'fetch_microsoft_advisories',
        'linux' => 'fetch_linux_advisories',
        'vmware' => 'fetch_vmware_advisories',
        'oracle' => 'fetch_oracle_advisories',
        'qualys' => 'fetch_qualys_advisories'
    ];

    $results = [];
    $total_new = 0;
    $total_processed = 0;
    $count = 0;
    $total_scrapers = count($scrapers);

    foreach ($scrapers as $key => $func) {
        $count++;
        update_status([
            "status" => "running",
            "percent" => round(($count / ($total_scrapers + 1)) * 100),
            "message" => "Running $key scraper...",
            "started_at" => date('Y-m-d H:i:s')
        ]);

        if (function_exists($func)) {
            $res = $func(true);
            $results[$key] = $res;
            if (isset($res['new'])) $total_new += $res['new'];
            if (isset($res['processed'])) $total_processed += $res['processed'];
        }
    }

    // Final Sync
    update_status([
        "status" => "running",
        "percent" => 95,
        "message" => "Syncing results to production...",
        "started_at" => date('Y-m-d H:i:s')
    ]);

    init_db($prod_db);
    sync_staging_to_production($staging_db);

    if (file_exists($staging_db)) {
        unlink($staging_db);
    }

    // Complete
    update_status([
        "status" => "success",
        "new" => $total_new,
        "processed" => $total_processed,
        "details" => $results,
        "completed_at" => date('Y-m-d H:i:s')
    ]);

} catch (Exception $e) {
    update_status([
        "status" => "error",
        "message" => $e->getMessage(),
        "completed_at" => date('Y-m-d H:i:s')
    ]);
}
