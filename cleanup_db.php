<?php
// cleanup_db.php
require_once 'db.php';

try {
    echo "Starting full cleanup...\n";
    
    // Check count before
    $count = $db->query("SELECT COUNT(*) FROM advisories")->fetchColumn();
    echo "Total advisories before: $count\n";
    
    // Delete ALL
    $stmt = $db->query("DELETE FROM advisories");
    
    // In some PDO configurations, rowCount might not be reliable for DELETE without WHERE, 
    // but for SQLite it usually works. We can also rely on the after-count.
    $deleted = $stmt->rowCount();
    
    echo "Deleted approx: $deleted advisories.\n";
    
    // Check count after
    $count_after = $db->query("SELECT COUNT(*) FROM advisories")->fetchColumn();
    echo "Remaining advisories: $count_after\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
