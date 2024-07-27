# Security Check Script

This PHP script performs a security check for a directory, identifying suspicious files and potential vulnerabilities, and reports on data being sent to unknown places. It checks for suspicious patterns in PHP, JavaScript, and HTML files, and ensures that certain files do not expose sensitive information or contain vulnerabilities.

## Features

- Recursively scans directories for suspicious files.
- Detects suspicious function calls (e.g., `eval()`, `base64_decode()`, `system()`).
- Identifies potential sensitive information exposure (e.g., API keys, passwords).
- Checks for potential SQL injection vulnerabilities.
- Verifies data being sent to unknown places.
- Checks DNS resolution and SSL certificate validity.
- Reports on directory listing security and file permissions.
- Displays the results in a user-friendly HTML report.

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/hamzadaoud/security_files_check.git
   cd security_files_check

2. **Example of db_connection.php:**
- <?php
- $servername = "localhost";
- $username = "your_username"; 
- $password = "your_password"; 
- $dbname = "your_database";
- $conn = new mysqli($servername, $username, $password, $dbname);
- if ($conn->connect_error) {
-    die("Connection failed: " . $conn->connect_error);
- }
- echo "Connected successfully";
- ?>
## How To use it
1. You Just have to put the file in your prefered location
2. Go to your Browser and write for example: localhost/security_check.php and it will start runing through all directories.
