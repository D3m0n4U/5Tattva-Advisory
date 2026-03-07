<?php
// index.php
require_once 'db.php';

$search = $_GET['search'] ?? '';
$sort = $_GET['sort'] ?? 'newest';
$source = $_GET['source'] ?? 'All';

$advisories = get_all_advisories(50, $search, $sort, $source);

// Helper function to pick a tag color based on source
function get_source_color($src)
{
    switch ($src) {
        case 'Cert-In':
            return '#2c3e50';
        case 'NVD':
            return '#005b9f';
        case 'CISA':
            return '#8b0000';
        case 'GitHub':
            return '#333333';
        case 'Microsoft':
            return '#00a4ef'; // Microsoft Blue
        case 'Linux':
            return '#e95420'; // Ubuntu Orange
        default:
            return '#666';
    }
}

if (isset($_GET['ajax'])) {
    if (empty($advisories)) {
        echo '<p style="text-align:center; grid-column: 1/-1; color: var(--text-secondary);">No advisories found matching "' . htmlspecialchars($search) . '"</p>';
    }
    foreach ($advisories as $adv) {
        $source_color = get_source_color($adv['source']);
        echo '<div class="advisory-card">';
        echo '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 5px;">';
        echo '<div class="tags" style="display:flex; gap: 5px;">';
        $sources = explode(',', $adv['source']);
        foreach ($sources as $s) {
            $s = trim($s);
            $source_color = get_source_color($s);
            echo '<span style="font-size: 0.75rem; background-color: ' . $source_color . '; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold;">' . htmlspecialchars($s) . '</span>';
        }
        echo '</div>';
        echo '</div>';
        echo '<div class="advisory-title">' . htmlspecialchars($adv['title']) . '</div>';
        echo '<div class="advisory-meta">';
        echo '<span><strong>Issued on:</strong> ' . htmlspecialchars($adv['issue_date']) . '</span>';
        echo '<span style="color: ' . ($adv['severity'] == 'High' || $adv['severity'] == 'Critical' ? 'var(--danger)' : 'var(--text-secondary)') . ';">' . htmlspecialchars($adv['severity']) . '</span>';
        echo '</div>';
        echo '<a href="advisory.php?id=' . $adv['id'] . '" class="btn-read">Read Advisory</a>';
        echo '</div>';
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advisory Dashboard | Five Tattva Cyberhub</title>
    <link rel="icon" href="images/favicon.png" type="image/png">
    <link rel="stylesheet" href="style.css?v=<?php echo time(); ?>">
    <script>
        // Auto-update every 1 hour (3600000 ms)
        setInterval(triggerUpdateCheck, 3600000);

        // Live Search Logic
        let debounceTimer;
        function debounce(func, timeout = 300){
            return (...args) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => { func.apply(this, args); }, timeout);
            };
        }

        function performSearch() {
            const query = document.getElementById('searchInput').value;
            const sort = document.getElementById('sortSelect').value;
            const sourceFilter = document.getElementById('sourceSelect').value;
            const grid = document.getElementById('advisoryGrid');
            
            grid.style.opacity = '0.5';

            fetch(`index.php?ajax=1&search=${encodeURIComponent(query)}&sort=${encodeURIComponent(sort)}&source=${encodeURIComponent(sourceFilter)}`)
                .then(res => res.text())
                .then(html => {
                    grid.innerHTML = html;
                    grid.style.opacity = '1';
                })
                .catch(err => console.error(err));
        }

        document.addEventListener('DOMContentLoaded', () => {
            const searchInput = document.getElementById('searchInput');
            const sortSelect = document.getElementById('sortSelect');
            const sourceSelect = document.getElementById('sourceSelect');

            searchInput.addEventListener('input', debounce(() => performSearch()));
            sortSelect.addEventListener('change', () => performSearch());
            sourceSelect.addEventListener('change', () => performSearch());
            
            // Trigger check on load
            triggerUpdateCheck();
        });
        
        function triggerUpdateCheck() {
             fetch('update.php')
                .then(response => response.json())
                .then(data => {
                    console.log('Auto-update check:', data);
                    if (data.new > 0) {
                        performSearch(); // Refresh grid if new items found
                    }
                })
                .catch(err => console.error('Auto-update failed:', err));
        }
    </script>
</head>
<body>
    <header>
        <div class="container brand-header">
            <div class="brand-logo">
                <img src="images/logo.png" alt="Five Tattva Logo" onerror="this.src=''; this.alt='Five Tattva';">
                <div class="brand-text">
                    <h1>Five Tattva Cyberhub</h1>
                    <span>Multi-Source Threat Intelligence Dashboard</span>
                </div>
            </div>
        </div>
    </header>

    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px;">
            <h2 style="color: var(--accent-color); margin: 0;">Latest Security Advisories</h2>
            
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <div class="search-box" style="display: flex; gap: 10px; align-items: center; background: white; padding: 5px 10px; border: 1px solid #ddd; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                    <svg width="20" height="20" fill="none" stroke="var(--text-secondary)" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                    <input type="text" id="searchInput" placeholder="Search ID, CVE, or Title..." value="<?php echo htmlspecialchars($search); ?>" style="border: none; outline: none; padding: 5px; width: 200px; font-size: 0.95rem;">
                </div>

                <select id="sourceSelect" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; background: white; cursor: pointer; font-size: 0.95rem; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                    <option value="All" <?php echo($source == 'All') ? 'selected' : ''; ?>>All Sources</option>
                    <option value="Cert-In" <?php echo($source == 'Cert-In') ? 'selected' : ''; ?>>Cert-In</option>
                    <option value="NVD" <?php echo($source == 'NVD') ? 'selected' : ''; ?>>NVD</option>
                    <option value="CISA" <?php echo($source == 'CISA') ? 'selected' : ''; ?>>CISA</option>
                    <option value="GitHub" <?php echo($source == 'GitHub') ? 'selected' : ''; ?>>GitHub</option>
                    <option value="Microsoft" <?php echo($source == 'Microsoft') ? 'selected' : ''; ?>>Microsoft</option>
                    <option value="Linux" <?php echo($source == 'Linux') ? 'selected' : ''; ?>>Linux / Ubuntu</option>
                </select>

                <select id="sortSelect" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; background: white; cursor: pointer; font-size: 0.95rem; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                    <option value="newest" <?php echo($sort == 'newest') ? 'selected' : ''; ?>>Newest First</option>
                    <option value="oldest" <?php echo($sort == 'oldest') ? 'selected' : ''; ?>>Oldest First</option>
                    <option value="severity" <?php echo($sort == 'severity') ? 'selected' : ''; ?>>Severity (High to Low)</option>
                </select>
            </div>
        </div>
        
        <div id="advisoryGrid" class="advisory-grid">
            <?php foreach ($advisories as $adv):
    $source_color = get_source_color($adv['source']); ?>
            <div class="advisory-card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 5px;">
                    <div class="tags" style="display:flex; gap: 5px;">
                        <?php
    $sources = explode(',', $adv['source']);
    foreach ($sources as $s):
        $s = trim($s);
        $source_color = get_source_color($s);
?>
                        <span style="font-size: 0.75rem; background-color: <?php echo $source_color; ?>; color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold;">
                            <?php echo htmlspecialchars($s); ?>
                        </span>
                        <?php
    endforeach; ?>
                    </div>
                </div>
                <div class="advisory-title"><?php echo htmlspecialchars($adv['title']); ?></div>
                <div class="advisory-meta">
                    <span><strong>Issued on:</strong> <?php echo htmlspecialchars($adv['issue_date']); ?></span>
                    <span style="color: <?php echo($adv['severity'] == 'High' || $adv['severity'] == 'Critical') ? 'var(--danger)' : 'var(--text-secondary)'; ?>">
                        <?php echo htmlspecialchars($adv['severity']); ?>
                    </span>
                </div>
                <a href="advisory.php?id=<?php echo $adv['id']; ?>" class="btn-read">Read Advisory</a>
            </div>
            <?php
endforeach; ?>
        </div>
    </div>

    <footer class="footer-brand">
        &copy; <?php echo date('Y'); ?> Five Tattva Cyberhub Security LLP. All Rights Reserved.
        <br>Shared Intelligence for a Safer Cyber Space.
    </footer>
</body>
</html>
