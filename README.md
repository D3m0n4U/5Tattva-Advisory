# Vulnerability Advisory Aggregator

A professional PHP-based dashboard and automation tool for aggregating, scraping, and managing security vulnerabilities and advisories from multiple authoritative threat intelligence sources.

## Features

- **Automated Scraping:** Periodically fetches high-fidelity security research and vendor advisories.
- **Deduplication:** Groups and consolidates advisories referring to the same CVE from different sources, preserving the richest descriptions.
- **Infinite Scroll Dashboard:** A high-performance dashboard (`index.php`) featuring automated data loading for a seamless browsing experience.
- **Smart Filtering:** Multi-source filtering, search (CVE/ID), and a default 7-day focused view to highlight recent threats.
- **Rich Typography:** Professionally formatted advisory details (`advisory.php`) with optimized layouts for complex vendor data (matrices, product lists).
- **Centralized Database:** Stores all intelligence in a lightweight, robust SQLite database.

## Supported Sources

The aggregator fetches intelligence from a growing list of premium sources:

- **CERT-In** (Indian Computer Emergency Response Team)
- **NVD** (National Vulnerability Database)
- **CISA** (Cybersecurity and Infrastructure Security Agency)
- **GitHub** (GitHub Security Advisories)
- **Microsoft** (Microsoft Security Response Center)
- **Red Hat / Ubuntu** (RHSA and USN Linux security notices)
- **Qualys** (Qualys Security Blog / TRU Research)
- **Oracle** (Oracle Critical Patch Updates)
- **VMware** (VMware Security Advisories)

## Requirements

- PHP 7.4 or higher
- SQLite3 Extension for PHP (`php-sqlite3`)
- cURL Extension for PHP (`php-curl`)
- DOM/XML Extension for PHP (`php-dom` or `php-xml`)

## Installation & Setup

1. **Deployment:**
   Place the project files in your web server's document root (e.g., `htdocs`, `/var/www/html/`) or any directory where you can run a local PHP server.

2. **Database Initialization:**
   The SQLite database (`database.sqlite`) is initialized and populated automatically upon the first scraper execution. 

3. **Start the Development Server:**
   ```bash
   php -S localhost:8000
   ```

## Usage

### 1. Web Dashboard
Navigate to `http://localhost:8000/index.php`. The dashboard defaults to the **Last 7 Days** of intelligence. Use the infinite scroll to browse older advisories effortlessly.

### 2. Updating Intelligence
To fetch the latest data, trigger the master update script:
- **Browser:** Visit `http://localhost:8000/update.php`
- **CLI:** Run `php update.php` - this is the recommended method for automation.

### 3. Automation
Set up a cron job (Linux) or a Scheduled Task (Windows) to execute `php /path/to/update.php` periodically (e.g., every 6 hours) to keep your dashboard synchronized with the latest threats.

## Project Structure

- `index.php`: Infinite scroll dashboard with advanced filtering.
- `advisory.php`: High-fidelity detail view for individual advisories.
- `update.php`: Orchestration script for all scrapers.
- `db.php`: Database abstraction layer and deduplication logic.
- `staging.sqlite`: Staging database for safe updates without downtime.
- `database.sqlite`: The production security intelligence repository.
- `style.css`: Modern, responsive UI styling.
- `scraper_*.php`: Specialized scripts for each intelligence source.
- `update_worker.php`: Background worker for asynchronous updates.
- `update_status.json`: Real-time status tracking for update processes.
- `README.md`: Project documentation.

## Troubleshooting

- **Process Locks:** If database updates fail, ensure no stale PHP processes are holding file locks (SQLite journal files).
- **Network Access:** Ensure the server has outbound internet access to reach vendor RSS feeds and APIs.
- **Extensions:** Verify `curl` and `sqlite3` are enabled in your `php.ini`.
