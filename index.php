<?php
// index.php
require_once 'db.php';

$search = $_GET['search'] ?? '';
$sort = $_GET['sort'] ?? 'newest';
$source = $_GET['source'] ?? 'All';
$time_range = $_GET['time_range'] ?? 'all';
$start_date = $_GET['start_date'] ?? '';
$end_date = $_GET['end_date'] ?? '';

$view = $_GET['view'] ?? 'grid';
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($page < 1)
    $page = 1;
$limit = 20;
$offset = ($page - 1) * $limit;

$advisories = get_all_advisories($limit, $offset, $search, $sort, $source, $time_range, $start_date, $end_date);
$total_advisories = get_advisories_count($search, $source, $time_range, $start_date, $end_date);
$total_pages = ceil($total_advisories / $limit);

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
        echo '<div style="grid-column: 1/-1; text-align: center; padding: 60px 20px; background: var(--card-bg); border-radius: 8px; border-top: 4px solid var(--text-secondary); box-shadow: 0 4px 15px rgba(0,0,0,0.05);">';
        echo '<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="1.5" style="margin-bottom: 20px; opacity: 0.5;">';
        echo '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
        echo '</svg>';
        echo '<h3 style="color: var(--primary-color); font-size: 1.25rem; margin: 0 0 10px 0; font-weight: 600;">No Threat Intelligence Found</h3>';
        if (!empty($search)) {
            echo '<p style="color: var(--text-secondary); margin: 0;">We couldn\'t find any advisories matching "<strong>' . htmlspecialchars($search) . '</strong>". Try adjusting your search or filters.</p>';
        }
        else {
            echo '<p style="color: var(--text-secondary); margin: 0;">There are no advisories available for the selected filters. Try broadening your criteria.</p>';
        }
        echo '</div>';
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
        echo '<div class="advisory-title-wrapper" data-tooltip="' . htmlspecialchars($adv['title']) . '">';
        echo '<div class="advisory-title">' . htmlspecialchars($adv['title']) . '</div>';
        echo '</div>';
        echo '<div class="advisory-meta">';
        echo '<div class="advisory-meta-date" data-tooltip="Issued on: ' . htmlspecialchars($adv['issue_date']) . '">';
        echo '<span><strong>Issued on:</strong> ' . htmlspecialchars($adv['issue_date']) . '</span>';
        echo '</div>';
        echo '<span style="color: ' . ($adv['severity'] == 'High' || $adv['severity'] == 'Critical' ? 'var(--danger)' : 'var(--text-secondary)') . ';">' . htmlspecialchars($adv['severity']) . '</span>';
        echo '</div>';
        echo '<a href="advisory.php?id=' . $adv['id'] . '" class="btn-read">Read Advisory</a>';
        echo '</div>';
    }

    // Output Pagination HTML
    if ($total_pages > 1) {
        $max_visible_pages = 5;
        $start_page = max(1, $page - floor($max_visible_pages / 2));
        $end_page = min($total_pages, $start_page + $max_visible_pages - 1);

        if ($end_page - $start_page + 1 < $max_visible_pages) {
            $start_page = max(1, $end_page - $max_visible_pages + 1);
        }

        echo '<div class="pagination" style="grid-column: 1/-1; display:flex; justify-content:center; align-items:center; gap:10px; margin-top:15px;">';

        if ($page > 1) {
            echo '<button onclick="goToPage(' . ($page - 1) . ')" class="btn-page">Prev</button>';
        }

        for ($i = $start_page; $i <= $end_page; $i++) {
            $active_class = ($i === $page) ? 'active' : '';
            echo '<button onclick="goToPage(' . $i . ')" class="btn-page ' . $active_class . '">' . $i . '</button>';
        }

        if ($page < $total_pages) {
            echo '<button onclick="goToPage(' . ($page + 1) . ')" class="btn-page">Next</button>';
        }

        echo '<span style="margin-left: 15px; color: var(--text-secondary); font-size:0.9rem;">Page ' . $page . ' of ' . $total_pages . '</span>';
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
        // Live Search Logic
        let debounceTimer;
        function debounce(func, timeout = 300){
            return (...args) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => { func.apply(this, args); }, timeout);
            };
        }

        let currentPage = 1;
        let currentView = 'grid'; // Default view

        function setView(view) {
            currentView = view;
            const container = document.getElementById('advisoryContainer');
            const gridBtn = document.getElementById('btnGrid');
            const listBtn = document.getElementById('btnList');
            
            if (view === 'list') {
                container.className = 'advisory-list';
                listBtn.classList.add('active');
                gridBtn.classList.remove('active');
            } else {
                container.className = 'advisory-grid';
                gridBtn.classList.add('active');
                listBtn.classList.remove('active');
            }
        }

        function performSearch(page = 1) {
            const query = document.getElementById('searchInput').value;
            const sortRadio = document.querySelector('input[name="sort"]:checked');
            const sort = sortRadio ? sortRadio.value : 'newest';
            
            const checkedSources = Array.from(document.querySelectorAll('input[name="source"]:checked')).map(cb => cb.value);
            let sourceFilter = 'All';
            if (checkedSources.length > 0 && !checkedSources.includes('All')) {
                sourceFilter = checkedSources.join(',');
            } else if (checkedSources.length === 0) {
                sourceFilter = 'None';
            }

            const timeRangeRadio = document.querySelector('input[name="time_range"]:checked');
            const timeRange = timeRangeRadio ? timeRangeRadio.value : 'all';
            
            let startDate = '';
            let endDate = '';
            if (timeRange === 'custom') {
                startDate = document.getElementById('customStartDate').value;
                endDate = document.getElementById('customEndDate').value;
            }

            const grid = document.getElementById('advisoryContainer');
            
            grid.style.opacity = '0.5';
            currentPage = page;

            fetch(`index.php?ajax=1&search=${encodeURIComponent(query)}&sort=${encodeURIComponent(sort)}&source=${encodeURIComponent(sourceFilter)}&time_range=${encodeURIComponent(timeRange)}&start_date=${encodeURIComponent(startDate)}&end_date=${encodeURIComponent(endDate)}&page=${currentPage}&view=${currentView}`)
                .then(res => res.text())
                .then(html => {
                    grid.innerHTML = html;
                    grid.style.opacity = '1';
                    
                    // Scroll to top of grid
                    grid.scrollIntoView({ behavior: 'smooth', block: 'start' });
                })
                .catch(err => console.error(err));
        }

        function goToPage(page) {
            performSearch(page);
        }

        function toggleCustomDateInputs() {
            const timeRange = document.querySelector('input[name="time_range"]:checked').value;
            const customDateContainer = document.getElementById('customDateContainer');
            if (timeRange === 'custom') {
                customDateContainer.style.display = 'block';
            } else {
                customDateContainer.style.display = 'none';
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            const searchInput = document.getElementById('searchInput');

            searchInput.addEventListener('input', debounce(() => performSearch()));
            
            document.querySelectorAll('input[name="sort"], input[name="time_range"]').forEach(radio => {
                radio.addEventListener('change', () => {
                    if (radio.name === 'time_range') {
                        toggleCustomDateInputs();
                    }
                    performSearch();
                });
            });

            document.getElementById('customStartDate').addEventListener('change', () => performSearch());
            document.getElementById('customEndDate').addEventListener('change', () => performSearch());

            const sourceAll = document.getElementById('sourceAll');
            const sourceCbs = document.querySelectorAll('.source-cb');

            sourceAll.addEventListener('change', (e) => {
                if(e.target.checked) {
                    sourceCbs.forEach(cb => cb.checked = true);
                } else {
                    sourceCbs.forEach(cb => cb.checked = false);
                }
                performSearch();
            });

            sourceCbs.forEach(cb => {
                cb.addEventListener('change', () => {
                    const allChecked = Array.from(sourceCbs).every(c => c.checked);
                    sourceAll.checked = allChecked;
                    performSearch();
                });
            });
        });
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
            
            <div class="header-advisories-title">
                <h2>Security Advisories</h2>
            </div>
        </div>
    </header>

    <div class="container main-layout">
        <div class="content-wrapper">
        <!-- Sidebar Panel for Filters -->
        <aside class="sidebar-filters">
            <!-- View Toggle Switch -->
            <div class="view-toggle" style="margin-bottom: 20px;">
                <div class="toggle-switch">
                    <button id="btnGrid" class="btn-view active" onclick="setView('grid')" title="Grid View">
                        <svg width="18" height="18" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M1 2.5A1.5 1.5 0 0 1 2.5 1h3A1.5 1.5 0 0 1 7 2.5v3A1.5 1.5 0 0 1 5.5 7h-3A1.5 1.5 0 0 1 1 5.5v-3zM2.5 2a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zm6.5.5A1.5 1.5 0 0 1 10.5 1h3A1.5 1.5 0 0 1 15 2.5v3A1.5 1.5 0 0 1 13.5 7h-3A1.5 1.5 0 0 1 9 5.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zM1 10.5A1.5 1.5 0 0 1 2.5 9h3A1.5 1.5 0 0 1 7 10.5v3A1.5 1.5 0 0 1 5.5 15h-3A1.5 1.5 0 0 1 1 13.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3zm6.5.5A1.5 1.5 0 0 1 10.5 9h3a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5h-3A1.5 1.5 0 0 1 9 13.5v-3zm1.5-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5h-3z"/>
                        </svg>
                    </button>
                    <button id="btnList" class="btn-view" onclick="setView('list')" title="List View">
                        <svg width="18" height="18" fill="currentColor" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M2.5 12a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5zm0-4a.5.5 0 0 1 .5-.5h10a.5.5 0 0 1 0 1H3a.5.5 0 0 1-.5-.5z"/>
                        </svg>
                    </button>
                </div>
            </div>

            <div class="filter-group">
                <h4>Search</h4>
                <div class="search-box" style="display: flex; gap: 10px; align-items: center; background: white; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                    <svg width="18" height="18" fill="none" stroke="var(--text-secondary)" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                    <input type="text" id="searchInput" placeholder="Search ID, CVE..." value="<?php echo htmlspecialchars($search); ?>" style="border: none; outline: none; padding: 0; width: 100%; font-size: 0.95rem;">
                </div>
            </div>

            <div class="filter-group">
                <h4>Source</h4>
                <?php
$selected_sources = explode(',', $source);
$is_all = (empty($source) || $source == 'All');
?>
                <label class="filter-option">
                    <input type="checkbox" id="sourceAll" name="source" value="All" <?php echo $is_all ? 'checked' : ''; ?>> All Sources
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="Cert-In" <?php echo($is_all || in_array('Cert-In', $selected_sources)) ? 'checked' : ''; ?>> Cert-In
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="NVD" <?php echo($is_all || in_array('NVD', $selected_sources)) ? 'checked' : ''; ?>> NVD
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="CISA" <?php echo($is_all || in_array('CISA', $selected_sources)) ? 'checked' : ''; ?>> CISA
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="GitHub" <?php echo($is_all || in_array('GitHub', $selected_sources)) ? 'checked' : ''; ?>> GitHub
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="Microsoft" <?php echo($is_all || in_array('Microsoft', $selected_sources)) ? 'checked' : ''; ?>> Microsoft
                </label>
                <label class="filter-option">
                    <input type="checkbox" class="source-cb" name="source" value="Linux" <?php echo($is_all || in_array('Linux', $selected_sources)) ? 'checked' : ''; ?>> Linux / Ubuntu
                </label>
            </div>

            <div class="filter-group">
                <h4>Sort By</h4>
                <label class="filter-option">
                    <input type="radio" name="sort" value="newest" <?php echo($sort == 'newest') ? 'checked' : ''; ?>> Newest First
                </label>
                <label class="filter-option">
                    <input type="radio" name="sort" value="oldest" <?php echo($sort == 'oldest') ? 'checked' : ''; ?>> Oldest First
                </label>
                <label class="filter-option">
                    <input type="radio" name="sort" value="severity" <?php echo($sort == 'severity') ? 'checked' : ''; ?>> Severity (High to Low)
                </label>
            </div>
            
            <div class="filter-group">
                <h4>Time Range</h4>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="all" <?php echo($time_range == 'all') ? 'checked' : ''; ?>> All Time
                </label>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="7days" <?php echo($time_range == '7days') ? 'checked' : ''; ?>> Last 7 Days
                </label>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="30days" <?php echo($time_range == '30days') ? 'checked' : ''; ?>> Last 30 Days
                </label>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="6months" <?php echo($time_range == '6months') ? 'checked' : ''; ?>> Last 6 Months
                </label>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="1year" <?php echo($time_range == '1year') ? 'checked' : ''; ?>> Last 1 Year
                </label>
                <label class="filter-option">
                    <input type="radio" name="time_range" value="custom" <?php echo($time_range == 'custom') ? 'checked' : ''; ?>> Custom Range
                </label>
                
                <div id="customDateContainer" style="display: <?php echo($time_range == 'custom') ? 'block' : 'none'; ?>; margin-top: 15px; padding: 12px; background-color: var(--bg-color); border-radius: 8px; border: 1px solid #e0e0e0;">
                    <div style="margin-bottom: 12px;">
                        <label style="display:block; font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 5px;">Start Date</label>
                        <input type="date" id="customStartDate" value="<?php echo htmlspecialchars($start_date); ?>" style="width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9rem; color: var(--text-primary); background-color: white; outline: none; transition: border-color 0.2s;" onfocus="this.style.borderColor='var(--primary-color)'" onblur="this.style.borderColor='#ddd'">
                    </div>
                    <div>
                        <label style="display:block; font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 5px;">End Date</label>
                        <input type="date" id="customEndDate" value="<?php echo htmlspecialchars($end_date); ?>" style="width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9rem; color: var(--text-primary); background-color: white; outline: none; transition: border-color 0.2s;" onfocus="this.style.borderColor='var(--primary-color)'" onblur="this.style.borderColor='#ddd'">
                    </div>
                </div>
            </div>
        </aside>

        <!-- Main Content for Advisories -->
        <div class="main-content">
        
        <div id="advisoryContainer" class="advisory-grid">
            <?php if (empty($advisories)): ?>
                <div style="grid-column: 1/-1; text-align: center; padding: 60px 20px; background: var(--card-bg); border-radius: 8px; border-top: 4px solid var(--text-secondary); box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="1.5" style="margin-bottom: 20px; opacity: 0.5;">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    <h3 style="color: var(--primary-color); font-size: 1.25rem; margin: 0 0 10px 0; font-weight: 600;">No Threat Intelligence Found</h3>
                    <?php if (!empty($search)): ?>
                        <p style="color: var(--text-secondary); margin: 0;">We couldn't find any advisories matching "<strong><?php echo htmlspecialchars($search); ?></strong>". Try adjusting your search or filters.</p>
                    <?php
    else: ?>
                        <p style="color: var(--text-secondary); margin: 0;">There are no advisories available for the selected filters. Try broadening your criteria.</p>
                    <?php
    endif; ?>
                </div>
            <?php
else: ?>
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
                    <div class="advisory-title-wrapper" data-tooltip="<?php echo htmlspecialchars($adv['title']); ?>">
                        <div class="advisory-title"><?php echo htmlspecialchars($adv['title']); ?></div>
                    </div>
                    <div class="advisory-meta">
                        <div class="advisory-meta-date" data-tooltip="Issued on: <?php echo htmlspecialchars($adv['issue_date']); ?>">
                            <span><strong>Issued on:</strong> <?php echo htmlspecialchars($adv['issue_date']); ?></span>
                        </div>
                        <span style="color: <?php echo($adv['severity'] == 'High' || $adv['severity'] == 'Critical') ? 'var(--danger)' : 'var(--text-secondary)'; ?>">
                            <?php echo htmlspecialchars($adv['severity']); ?>
                        </span>
                    </div>
                    <a href="advisory.php?id=<?php echo $adv['id']; ?>" class="btn-read">Read Advisory</a>
                </div>
                <?php
    endforeach; ?>
            <?php
endif; ?>
            
            <?php if ($total_pages > 1): ?>
                <?php
    $max_visible_pages = 5;
    $start_page = max(1, $page - floor($max_visible_pages / 2));
    $end_page = min($total_pages, $start_page + $max_visible_pages - 1);

    if ($end_page - $start_page + 1 < $max_visible_pages) {
        $start_page = max(1, $end_page - $max_visible_pages + 1);
    }
?>
                <div class="pagination" style="grid-column: 1/-1; display:flex; justify-content:center; align-items:center; gap:10px; margin-top:15px;">
                    <?php if ($page > 1): ?>
                        <button onclick="goToPage(<?php echo $page - 1; ?>)" class="btn-page">Prev</button>
                    <?php
    endif; ?>
                    
                    <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                        <button onclick="goToPage(<?php echo $i; ?>)" class="btn-page <?php echo($i === $page) ? 'active' : ''; ?>"><?php echo $i; ?></button>
                    <?php
    endfor; ?>
                    
                    <?php if ($page < $total_pages): ?>
                        <button onclick="goToPage(<?php echo $page + 1; ?>)" class="btn-page">Next</button>
                    <?php
    endif; ?>
                    
                    <span style="margin-left: 15px; color: var(--text-secondary); font-size:0.9rem;">Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                </div>
            <?php
endif; ?>
        </div>
        </div>
        </div>
    </div>

    <footer class="footer-brand">
        &copy; <?php echo date('Y'); ?> Five Tattva Cyberhub Security LLP. All Rights Reserved.
        <br>Shared Intelligence for a Safer Cyber Space.
    </footer>
</body>
</html>
