<?php
// update.php
// Triggers the background update worker or returns current status

$status_file = __DIR__ . '/update_status.json';

// Handle AJAX status requests
if (isset($_GET['check_status'])) {
    header('Content-Type: application/json');
    if (file_exists($status_file)) {
        echo file_get_contents($status_file);
    } else {
        echo json_encode(["status" => "idle"]);
    }
    exit;
}

// Trigger the update
$status = ["status" => "idle"];
if (file_exists($status_file)) {
    $status = json_decode(file_get_contents($status_file), true);
}

if ($status['status'] === 'running') {
    $result = [
        "status" => "running",
        "message" => "An update is already in progress.",
        "percent" => $status['percent'] ?? 0
    ];
} else {
    // Cross-platform background execution
    $worker_path = __DIR__ . '/update_worker.php';
    
    if (stristr(PHP_OS, 'WIN')) {
        // Windows: popen with start /B
        pclose(popen("start /B php \"$worker_path\" > nul 2>&1", "r"));
    } else {
        // Linux/Unix: nohup and &
        exec("php \"$worker_path\" > /dev/null 2>&1 &");
    }

    $result = [
        "status" => "started",
        "message" => "Update started in the background."
    ];
}

header('Content-Type: application/json');
echo json_encode($result);
?>
