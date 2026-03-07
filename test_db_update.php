<?php
require 'db.php';
global $db;
$stmt = $db->query("SELECT source, original_link FROM advisories WHERE id = 1110");
print_r($stmt->fetch());
?>
