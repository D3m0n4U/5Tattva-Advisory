<?php
// advisory.php
require_once 'db.php';

$id = $_GET['id'] ?? 0;
$adv = get_advisory($id);

if (!$adv)
    die("Advisory not found.");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($adv['source_id']); ?> | Five Tattva Cyberhub</title>
    <link rel="icon" href="images/favicon.png" type="image/png">
    <link rel="stylesheet" href="style.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="container brand-header">
            <div class="brand-logo">
                <img src="images/logo.png" alt="Five Tattva Logo">
                <div class="brand-text">
                    <h1>Five Tattva Cyberhub</h1>
                    <span>Security Warning & Advisory</span>
                </div>
            </div>
        </div>
    </header>

    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <a href="index.php" class="btn-back" style="margin-bottom: 0;">&larr; Back to Dashboard</a>
            <button onclick="window.print()" class="btn-print">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path></svg>
                Print Advisory
            </button>
        </div>
        
        <div class="detail-header">
            <h1 style="color: var(--primary-color); margin:0;"><?php echo htmlspecialchars($adv['title']); ?></h1>
            <div style="margin-top: 10px; color: var(--text-secondary);">
                <strong>ID:</strong> <?php echo htmlspecialchars($adv['source_id']); ?> | 
                <strong>Released:</strong> <?php echo htmlspecialchars($adv['issue_date']); ?>
            </div>
        </div>

        <div class="detail-content">
            <!-- Injecting HTML content captured from Cert-IN. 
                 Using htmlspecialchars is NOT done here because we want to render the table structure.
                 In a real world scenario, this needs HTMLPurifier to prevent XSS. 
            -->
            <style>
                .detail-content > *:last-child { margin-bottom: 0 !important; }
            </style>
            <?php echo $adv['description']; ?>
            
            <hr style="margin: 5px 0; border: 0; border-top: 1px solid #eee;">
            <div style="margin-top: 5px;">
                <strong>Original Sources:</strong>
                <ul style="margin: 5px 0; padding-left: 20px;">
                    <?php
$links = explode("\n", $adv['original_link']);
foreach ($links as $link) {
    $link = trim($link);
    if (!empty($link)) {
        echo '<li><a href="' . htmlspecialchars($link) . '" target="_blank">' . htmlspecialchars($link) . '</a></li>';
    }
}
?>
                </ul>
            </div>
        </div>
    </div>

    <footer class="footer-brand">
        Prepared by Five Tattva Cyberhub Security LLP
    </footer>
</body>
</html>
