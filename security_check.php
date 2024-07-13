<?php
// security_check.php

// Include database connection (adjust path as needed)
include 'db/db_connection.php';

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Function to recursively scan directories for suspicious files
function scan_directory($dir) {
    $suspicious_files = array();
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

    foreach ($iterator as $file) {
        if ($file->isFile()) {
            $filename = $file->getPathname();

            // Check if file extension is suspicious (adjust as needed)
            if (preg_match('/\.(php|js|html)$/i', $filename)) {
                // Check file contents for suspicious patterns
                $content = file_get_contents($filename);
                
                // Initialize reasons for concern
                $reasons = array();

                // Check for eval(), base64_decode(), or system() calls
                if (preg_match('/(eval\(|base64_decode|system\()/i', $content)) {
                    $reasons[] = "Suspicious function calls detected.";
                }
                
                // Check for sensitive information exposure (example: API keys)
                if (preg_match('/(api_key|secret_key|password|DB_PASSWORD)/i', $content)) {
                    $reasons[] = "Sensitive information exposure detected.";
                }
                
                // Check for SQL injection vulnerabilities (example: $_GET['user_input'] used in queries)
                if (preg_match('/\$_(GET|POST)\[\'([a-zA-Z_]+)\'\]/i', $content)) {
                    $reasons[] = "Potential SQL injection vulnerability detected.";
                }

                // If reasons found, add suspicious file with reasons
                if (!empty($reasons)) {
                    $excerpt = substr($content, 0, 200); // Extract first 200 characters
                    $suspicious_files[$filename] = array(
                        'reasons' => $reasons,
                        'excerpt' => $excerpt
                    );
                }
            }
        }
    }

    return $suspicious_files;
}

// Check data sending to unknown places
function check_data_sending() {
    $output = '';

    // Check if ports 80 (HTTP) and 443 (HTTPS) are open and connected
    $ports = array(80, 443);

    foreach ($ports as $port) {
        $fp = @fsockopen('34.46.68.41', $port, $errno, $errstr, 1); // Adjust IP as necessary
        if ($fp) {
            $output .= "<span class='text-success'>Port $port is open and connected.</span><br>";
            fclose($fp);
        } else {
            $output .= "<span class='text-danger'>Port $port is closed.</span><br>";
        }
    }

    // Check DNS resolution
$dns_check = dns_get_record('project-xlabs.online', DNS_A + DNS_AAAA);
if (!empty($dns_check)) {
    $output .= "<span class='text-success'>DNS resolution for project-xlabs.online successful.</span><br>";
} else {
    $output .= "<span class='text-danger'>DNS resolution for project-xlabs.online failed.</span><br>";
}

// Check SSL certificate validity
$ssl_check = stream_context_create(array("ssl" => array("capture_peer_cert" => true)));
$res = stream_socket_client("ssl://project-xlabs.online:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ssl_check);
if ($res) {
    $context = stream_context_get_params($res);
    $cert_info = openssl_x509_parse($context['options']['ssl']['peer_certificate']);
    $valid_from = date('Y-m-d H:i:s', $cert_info['validFrom_time_t']);
    $valid_to = date('Y-m-d H:i:s', $cert_info['validTo_time_t']);
    $output .= "<span class='text-success'>SSL certificate valid until $valid_to.</span><br>";
} else {
    $output .= "<span class='text-danger'>SSL connection failed or certificate invalid.</span><br>";
}
function check_directory_listing($dir) {
    $output = '';

    if (!is_readable($dir) || !is_executable($dir) || !is_writable($dir)) {
        $output .= "<span class='text-danger'>Directory $dir is not properly secured.</span><br>";
    } else {
        $output .= "<span class='text-success'>Directory $dir is properly secured.</span><br>";
    }

    return $output;
}
function check_for_xss($content) {
    $output = '';

    if (preg_match('/<script[^>]*>(.*?)<\/script>/is', $content)) {
        $output .= "<span class='text-danger'>Potential XSS vulnerability detected.</span><br>";
    }

    return $output;
}
function check_file_permissions($filename) {
    $output = '';

    $perms = fileperms($filename);
    if (($perms & 0x0004) || ($perms & 0x0002)) {
        $output .= "<span class='text-danger'>File $filename has insecure permissions.</span><br>";
    } else {
        $output .= "<span class='text-success'>File $filename has secure permissions.</span><br>";
    }

    return $output;
}

    return $output;
}


// Check for potential breaches or suspicious activities in all directories
function check_for_breaches() {
    // Directory to start scanning (adjust as needed)
    $start_dir = '.';
    $suspicious_files = scan_directory($start_dir);
    return $suspicious_files;
}

// Main script execution
$unknown_data = check_data_sending();
$potential_breaches = check_for_breaches();

// Close database connection if used
if (isset($conn)) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check Report</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">

    <style>
        .card-body pre {
            white-space: pre-wrap;
        }
        .table-selectable {
            border: 1px solid #dee2e6; /* Table border */
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 1rem;
            background-color: #fff;
        }
        .table-selectable th,
        .table-selectable td {
            border: 1px solid #dee2e6; /* Cell borders */
            padding: .75rem;
            vertical-align: top;
            border-top: 1px solid #dee2e6;
        }
        .table-selectable thead th {
            vertical-align: bottom;
            border-bottom: 2px solid #dee2e6; /* Header row bottom border */
        }
        .table-selectable tbody + tbody {
            border-top: 2px solid #dee2e6;
        }
        .table-selectable .collapse.show {
            display: table-row; /* Ensure collapse content shows as table row */
        }
        .table-selectable .selected {
            background-color: #cce5ff;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">Security Check Report</h1>
        
        <div class="card mb-4">
            <div class="card-header">
                Checking for data sent to unknown places
            </div>
            <div class="card-body">
                <?php echo $unknown_data; ?>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                Checking for potential breaches or suspicious files
            </div>
            <div class="card-body">
                <?php if (!empty($potential_breaches)): ?>
                    <div class="table-responsive">
                        <table class="table table-hover table-selectable">
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Reasons for Concern</th>
                                    <th>Last Modified</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($potential_breaches as $file => $details): ?>
                                    <tr data-toggle="collapse" data-target="#details-<?php echo md5($file); ?>" aria-expanded="false" aria-controls="details-<?php echo md5($file); ?>">
                                        <td><?php echo $file; ?></td>
                                        <td>
                                            <?php foreach ($details['reasons'] as $reason): ?>
                                                <div class="alert alert-danger" role="alert">
                                                    <i class="fas fa-exclamation-triangle"></i> <?php echo $reason; ?>
                                                </div>
                                            <?php endforeach; ?>
                                        </td>
                                        <td><?php echo date('Y-m-d H:i:s', filemtime($file)); ?></td>
                                    </tr>
                                    <tr class="collapse" id="details-<?php echo md5($file); ?>">
                                        <td colspan="3">
                                            <pre><?php echo htmlentities(substr($details['excerpt'], 0, 500)); ?></pre>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <p class="alert alert-success">No suspicious files found.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <!-- Footer -->
    <footer class="footer mt-auto py-3">
        <div class="container">
            <span class="text-muted">Generated on <?php echo date('Y-m-d H:i:s'); ?></span>
        </div>
    </footer>

    <!-- Bootstrap JS and dependencies (optional) -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js" integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
    $(document).ready(function() {
        // Enable row selection and toggle details
        $('.table-selectable tbody tr').click(function(event) {
            event.preventDefault(); // Prevent default action
            
            var $thisRow = $(this);
            var $collapse = $thisRow.next('.collapse');

            // Toggle the collapse element for this row
            $collapse.collapse('toggle');

            // Log the state after toggle
            console.log("Clicked row:", $thisRow.index(), "Collapse element:", $collapse.length);
            console.log("After toggle, is collapsed:", !$collapse.hasClass('show'));
        });
    });
</script>

</body>
</html>
