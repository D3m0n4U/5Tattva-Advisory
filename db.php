<?php
// db.php
// Five Tattva Cyberhub Security LLP - Cert-IN Automation

$db_file = __DIR__ . '/database.sqlite';

try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Create table if not exists with strict schema
    $query = "CREATE TABLE IF NOT EXISTS advisories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id TEXT UNIQUE NOT NULL,
        source TEXT NOT NULL,
        cve_ids TEXT,
        title TEXT,
        severity TEXT,
        issue_date TEXT,
        description TEXT,
        software_affected TEXT,
        solution TEXT,
        original_link TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )";

    $db->exec($query);

}
catch (PDOException $e) {
    die("Database Connection Error: " . $e->getMessage());
}

function extract_cves($text)
{
    preg_match_all('/CVE-\d{4}-\d+/i', $text, $matches);
    if (!empty($matches[0])) {
        // Upper case and unique
        $cves = array_unique(array_map('strtoupper', $matches[0]));
        return implode(',', $cves);
    }
    return '';
}

function save_advisory($data)
{
    global $db;

    // Auto-extract CVEs from description if not provided explicitly, or merge them.
    $detected_cves = extract_cves($data[':description'] ?? '');
    $existing_cves = $data[':cve_ids'] ?? '';

    $all_cves = array_filter(array_unique(explode(',', $detected_cves . ',' . $existing_cves)));
    $final_cves = implode(',', $all_cves);
    $data[':cve_ids'] = $final_cves;

    // Deduplication Check
    if (!empty($final_cves)) {
        $cve_array = explode(',', $final_cves);
        foreach ($cve_array as $cve) {
            $cve = trim($cve);
            if (empty($cve))
                continue;

            // Check if this CVE already exists in the database
            // LIKE %CVE% is used because cve_ids is a comma separated string
            $stmt = $db->prepare("SELECT id, source_id, source, original_link FROM advisories WHERE cve_ids LIKE :cve OR title LIKE :cve");
            $stmt->execute([':cve' => "%$cve%"]);
            $existing = $stmt->fetch();

            if ($existing) {
                $existing_sources = explode(',', $existing['source']);
                $existing_sources = array_map('trim', $existing_sources);
                $new_source = trim($data[':source']);

                if (!in_array($new_source, $existing_sources)) {
                    $existing_sources[] = $new_source;
                    $updated_sources = implode(', ', $existing_sources);

                    // Update the source list
                    $update_stmt = $db->prepare('UPDATE advisories SET source = :updated_sources WHERE id = :id');
                    $update_stmt->execute([
                        ':updated_sources' => $updated_sources,
                        ':id' => $existing['id']
                    ]);
                    return 0; // Still returning 0 for "not inherently new advisory" but source updated
                }
                else {
                    // If it's already in the sources, and it is NVD or Microsoft, let's update the description to get the rich HTML
                    // (Only for these sources as requested to get full page info)
                    if (in_array($new_source, ['NVD', 'Microsoft', 'CISA'])) {
                        $update_stmt = $db->prepare('UPDATE advisories SET description = :description, software_affected = :software_affected WHERE id = :id');
                        $update_stmt->execute([
                            ':description' => $data[':description'],
                            ':software_affected' => $data[':software_affected'],
                            ':id' => $existing['id']
                        ]);
                    }
                    return 0; // Duplicate
                }
            }
        }
    }

    $stmt = $db->prepare("INSERT OR IGNORE INTO advisories (source_id, source, cve_ids, title, severity, issue_date, description, software_affected, solution, original_link) VALUES (:source_id, :source, :cve_ids, :title, :severity, :issue_date, :description, :software_affected, :solution, :original_link)");
    $stmt->execute($data);
    return $stmt->rowCount(); // Returns 1 if inserted, 0 if ignored (duplicate)
}

function get_all_advisories($limit = 20, $offset = 0, $search = '', $sort = 'newest', $source_filter = '', $time_range = 'all', $start_date = '', $end_date = '')
{
    global $db;

    $query = "SELECT * FROM advisories WHERE 1=1";
    $params = [];

    // Search
    if (!empty($search)) {
        $query .= " AND (title LIKE :search OR source_id LIKE :search OR cve_ids LIKE :search)";
        $params[':search'] = "%$search%";
    }

    // Source Filter
    if (!empty($source_filter) && $source_filter !== 'All') {
        $sources = array_map('trim', explode(',', $source_filter));
        if (count($sources) > 0) {
            $source_clauses = [];
            foreach ($sources as $i => $src) {
                if (!empty($src)) {
                    $source_clauses[] = "source LIKE :source_$i";
                    $params[":source_$i"] = "%$src%";
                }
            }
            if (!empty($source_clauses)) {
                $query .= " AND (" . implode(' OR ', $source_clauses) . ")";
            }
        }
    }

    // Time Range Filter
    if ($time_range !== 'all') {
        switch ($time_range) {
            case '7days':
                $query .= " AND issue_date >= date('now', '-7 days')";
                break;
            case '30days':
                $query .= " AND issue_date >= date('now', '-30 days')";
                break;
            case '6months':
                $query .= " AND issue_date >= date('now', '-6 months')";
                break;
            case '1year':
                $query .= " AND issue_date >= date('now', '-1 year')";
                break;
            case 'custom':
                if (!empty($start_date) && !empty($end_date)) {
                    $query .= " AND issue_date BETWEEN :start_date AND :end_date";
                    $params[':start_date'] = $start_date;
                    $params[':end_date'] = $end_date;
                }
                else if (!empty($start_date)) {
                    $query .= " AND issue_date >= :start_date";
                    $params[':start_date'] = $start_date;
                }
                else if (!empty($end_date)) {
                    $query .= " AND issue_date <= :end_date";
                    $params[':end_date'] = $end_date;
                }
                break;
        }
    }

    // Sort
    switch ($sort) {
        case 'oldest':
            $query .= " ORDER BY issue_date ASC, id ASC";
            break;
        case 'severity':
            // Custom sort: Critical -> High -> Medium -> Low
            $query .= " ORDER BY CASE severity 
                        WHEN 'Critical' THEN 1 
                        WHEN 'High' THEN 2 
                        WHEN 'Medium' THEN 3 
                        WHEN 'Low' THEN 4 
                        WHEN 'Info' THEN 5
                        ELSE 6 END ASC, id DESC";
            break;
        case 'newest':
        default:
            $query .= " ORDER BY issue_date DESC, id DESC";
            break;
    }

    $query .= " LIMIT :limit OFFSET :offset";
    $params[':limit'] = $limit;
    $params[':offset'] = $offset;

    $stmt = $db->prepare($query);

    foreach ($params as $key => $val) {
        $type = ($key === ':limit' || $key === ':offset') ?PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $val, $type);
    }

    $stmt->execute();
    return $stmt->fetchAll();
}

function get_advisories_count($search = '', $source_filter = '', $time_range = 'all', $start_date = '', $end_date = '')
{
    global $db;

    $query = "SELECT COUNT(*) FROM advisories WHERE 1=1";
    $params = [];

    // Search
    if (!empty($search)) {
        $query .= " AND (title LIKE :search OR source_id LIKE :search OR cve_ids LIKE :search)";
        $params[':search'] = "%$search%";
    }

    // Source Filter
    if (!empty($source_filter) && $source_filter !== 'All') {
        $sources = array_map('trim', explode(',', $source_filter));
        if (count($sources) > 0) {
            $source_clauses = [];
            foreach ($sources as $i => $src) {
                if (!empty($src)) {
                    $source_clauses[] = "source LIKE :source_$i";
                    $params[":source_$i"] = "%$src%";
                }
            }
            if (!empty($source_clauses)) {
                $query .= " AND (" . implode(' OR ', $source_clauses) . ")";
            }
        }
    }

    // Time Range Filter
    if ($time_range !== 'all') {
        switch ($time_range) {
            case '7days':
                $query .= " AND issue_date >= date('now', '-7 days')";
                break;
            case '30days':
                $query .= " AND issue_date >= date('now', '-30 days')";
                break;
            case '6months':
                $query .= " AND issue_date >= date('now', '-6 months')";
                break;
            case '1year':
                $query .= " AND issue_date >= date('now', '-1 year')";
                break;
            case 'custom':
                if (!empty($start_date) && !empty($end_date)) {
                    $query .= " AND issue_date BETWEEN :start_date AND :end_date";
                    $params[':start_date'] = $start_date;
                    $params[':end_date'] = $end_date;
                }
                else if (!empty($start_date)) {
                    $query .= " AND issue_date >= :start_date";
                    $params[':start_date'] = $start_date;
                }
                else if (!empty($end_date)) {
                    $query .= " AND issue_date <= :end_date";
                    $params[':end_date'] = $end_date;
                }
                break;
        }
    }

    $stmt = $db->prepare($query);
    foreach ($params as $key => $val) {
        $stmt->bindValue($key, $val, PDO::PARAM_STR);
    }

    $stmt->execute();
    return $stmt->fetchColumn();
}

function get_advisory($id)
{
    global $db;
    $stmt = $db->prepare("SELECT * FROM advisories WHERE id = :id");
    $stmt->execute([':id' => $id]);
    return $stmt->fetch();
}
?>
