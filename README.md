# Vulnerability Advisory Aggregator

A PHP-based dashboard and automation tool for aggregating, scraping, and managing security vulnerabilities and advisories from multiple authoritative sources.

## Features

- **Automated Scraping:** Periodically fetches the latest security advisories from multiple sources.
- **Deduplication:** Groups and consolidates advisories referring to the same CVE from different sources.
- **Centralized Database:** Stores all advisories in a lightweight SQLite database (`database.sqlite`).
- **Web Dashboard:** A responsive user interface (`index.php`) to filter, search, and view security advisories.
- **Detailed Views:** Individual pages for each advisory (`advisory.php`) with rich description and metadata.

## Supported Sources

The aggregator fetches security advisories from:

- **CERT-In** (Indian Computer Emergency Response Team)
- **NVD** (National Vulnerability Database)
- **CISA** (Cybersecurity and Infrastructure Security Agency)
- **GitHub** (GitHub Security Advisories)
- **Microsoft** (Microsoft Security Response Center)
- **Ubuntu/Linux** (Ubuntu Security Notices)

## Requirements

- PHP 7.4 or higher
- SQLite3 Extension for PHP (`php-sqlite3`)
- cURL Extension for PHP (`php-curl`)
- DOM Extension for PHP (`php-dom` or `php-xml` for HTML parsing)

## Installation & Setup

1. **Clone or Download the Repository:**
   Place the project files in your web server's document root (e.g., `htdocs`, `/var/www/html/`) or any directory where you can run a local PHP server.

2. **Database Initialization:**
   The SQLite database (`database.sqlite`) is usually created and populated automatically when the scrapers run. 

3. **Start the Development Server (Optional):**
   If you aren't using Apache or Nginx, you can use the built-in PHP server:
   ```bash
   php -S localhost:8000
   ```

## Usage

### 1. Web Dashboard
Navigate to the root URL (e.g., `http://localhost:8000/index.php`) in your web browser. You can filter advisories by their source, search by CVE ID, and open them to read full details.

### 2. Updating Advisories Manually
To fetch the latest advisories, you can trigger the update script:
- **Via Browser:** Visit `http://localhost:8000/update.php`
- **Via CLI:** Run `php update.php` in your terminal.

The `update.php` script executes all the individual `scraper_*.php` scripts and outputs a JSON summary of new and processed advisories.

### 3. Automation
For continuous operation in a production environment, set up a cron job (Linux) or a Scheduled Task (Windows) to hit `update.php` or execute `php /path/to/update.php` periodically (e.g., every 6 hours).

## Project Structure

- `index.php`: Main dashboard interface.
- `advisory.php`: Displays details for a single advisory.
- `update.php`: Triggers all scraping scripts and reports the results.
- `db.php`: SQLite database connection and helper functions.
- `cleanup_db.php`: Utility script for cleaning up database records.
- `style.css`: Stylesheet for the web dashboard.
- `scraper_*.php`: Individual scraper scripts for each supported source.
- `database.sqlite`: The SQLite database file.

## Troubleshooting

- **Permissions:** Ensure the PHP process has read and write permissions to the project directory to create/update `database.sqlite`.
- **Missing Extensions:** If scraping fails, ensure that `curl` and `dom` PHP extensions are enabled in your `php.ini`.
