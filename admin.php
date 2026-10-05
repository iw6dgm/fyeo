<?php
/**
 * admin.php - Minimal administrative page for the AES one-off vault.
 *
 * FEATURES:
 *   - HTTP Basic Auth protected (password_hash / password_verify)
 *   - Displays total records in the `payloads` table
 *   - Displays records eligible for purge (older than 30 days)
 *   - Button to manually execute the purge
 *
 * REQUIREMENTS:
 *   - PHP 7.0+
 *   - pdo_sqlite extension
 *   - Same DB file as encrypt.php (adjust DB_PATH if needed)
 *
 * AUTH MODEL:
 *   - ADMIN_USER holds the username (plaintext, in the source file).
 *   - ADMIN_HASH holds a bcrypt/Argon2 digest produced by password_hash().
 *   - Login is verified with password_verify(), which is constant-time and
 *     resistant to timing attacks.
 *   - HTTPS is required: Basic Auth sends credentials in Base64 on every
 *     request.
 *
 * HOW TO SET UP CREDENTIALS:
 *   1. Choose a username and password.
 *   2. Run on the command line:
 *
 *        php -r 'echo password_hash("YOUR_PASSWORD_HERE", PASSWORD_DEFAULT), PHP_EOL;'
 *
 *      This prints a digest like:
 *        $2y$10$wH8QZ8kQ9z8xL5N1vV5dOeQxQ0Y6zJ1kYQ1e0v3nB8c2Y5mX9fZ3u
 *
 *   3. Update ADMIN_USER and ADMIN_HASH below with your values.
 *
 *   The password itself is never stored anywhere — only its hash.
 *
 * NOTE: Because HTTP Basic Auth resends the password on every request, the
 *       hashing cost is paid on every request. With PASSWORD_BCRYPT defaults
 *       (~60ms on modern hardware), this is acceptable for a low-traffic
 *       admin page but would be a bottleneck under sustained load. If you
 *       expect many requests, cache a session cookie after the first
 *       successful verify instead of re-verifying each time.
 */

// ===========================================================================
// CONFIG — CHANGE THESE VALUES
// ===========================================================================

// SQLite database (must match encrypt.php)
define('DB_PATH', __DIR__ . '/payloads.sqlite');

// Payload retention (must match encrypt.php — 30 days)
define('PAYLOAD_RETENTION', 30 * 86400);

// --- Credentials ------------------------------------------------------------
// The example below uses the username "admin" and password "ChangeMe123!".
//
// The hash shown here was produced with:
//   php -r 'echo password_hash("ChangeMe123!", PASSWORD_DEFAULT), PHP_EOL;'
//
// It will NOT match if you copy-paste it — hashes are salted, so a new
// password_hash() run always produces a different digest. You MUST regenerate
// the hash for your own password and replace ADMIN_HASH.
//
// The value below is provided so that the file is syntactically valid and
// so you can see the expected format. Replace it before exposing this page.
//
define('ADMIN_USER', 'admin');
define('ADMIN_HASH', '$2y$10$e0MYzXyjpJS7Pd0RVvHwHe1HlCS4bZJ18JuywdBm7uK1RQ9UQFHr6'); // placeholder: "ChangeMe123!" — REGENERATE

// ===========================================================================
// AUTH
// ===========================================================================
function require_basic_auth() {
    $user = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
    $pass = isset($_SERVER['PHP_AUTH_PW'])   ? $_SERVER['PHP_AUTH_PW']   : '';

    // Constant-time username comparison (avoids trivial enumeration)
    $userOk = hash_equals(ADMIN_USER, $user);

    // password_verify is already constant-time with respect to the hash;
    // we still combine with $userOk so a wrong username always fails.
    $passOk = false;
    if ($userOk) {
        $passOk = password_verify($pass, ADMIN_HASH);
    }

    if (!$userOk || !$passOk) {
        header('WWW-Authenticate: Basic realm="AES Vault Admin"');
        header('HTTP/1.1 401 Unauthorized');
        header('Content-Type: text/plain; charset=utf-8');
        echo "Authentication required.\n";
        exit;
    }
}

require_basic_auth();

// ===========================================================================
// DB
// ===========================================================================
function db_open() {
    try {
        $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
        $pdo->exec('PRAGMA busy_timeout = 3000');
        return $pdo;
    } catch (PDOException $e) {
        return null;
    }
}

// ===========================================================================
// ACTIONS
// ===========================================================================
$pdo = db_open();
$flash = null;   // ['type' => 'ok'|'err', 'msg' => '...']

if ($pdo === null) {
    $flash = ['type' => 'err', 'msg' => 'Database unavailable: ' . DB_PATH];
} else {
    // Handle manual purge (POST)
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])
        && $_POST['action'] === 'purge') {

        $cutoff = time() - PAYLOAD_RETENTION;
        try {
            $stmt = $pdo->prepare('DELETE FROM payloads WHERE created_at < :c');
            $stmt->execute([':c' => $cutoff]);
            $deleted = $stmt->rowCount();
            $flash = [
                'type' => 'ok',
                'msg'  => 'Purge complete. Deleted ' . $deleted . ' record(s) older than 30 days.',
            ];
        } catch (Throwable $e) {
            $flash = ['type' => 'err', 'msg' => 'Purge failed: ' . $e->getMessage()];
        }
    }
}

// ===========================================================================
// STATS
// ===========================================================================
$totalCount  = 0;
$purgeable   = 0;
$cutoff      = time() - PAYLOAD_RETENTION;

if ($pdo !== null) {
    try {
        $totalCount = (int)$pdo->query('SELECT COUNT(*) FROM payloads')->fetchColumn();

        $stmt = $pdo->prepare('SELECT COUNT(*) FROM payloads WHERE created_at < :c');
        $stmt->execute([':c' => $cutoff]);
        $purgeable = (int)$stmt->fetchColumn();
    } catch (Throwable $e) {
        if ($flash === null) {
            $flash = ['type' => 'err', 'msg' => 'Stats query failed: ' . $e->getMessage()];
        }
    }
}

// ===========================================================================
// RENDER (minimal HTML)
// ===========================================================================
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AES Vault — Admin</title>
<style>
    body {
        font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
        background: #f5f7fb;
        color: #1d3d4f;
        margin: 0;
        padding: 40px 20px;
        display: flex;
        justify-content: center;
    }
    .box {
        background: #fff;
        border-radius: 16px;
        box-shadow: 0 12px 30px -12px rgba(0,20,30,.25);
        padding: 28px 32px;
        max-width: 560px;
        width: 100%;
    }
    h1 {
        margin: 0 0 8px;
        font-size: 1.5rem;
        font-weight: 600;
        color: #0b2b3b;
    }
    .sub {
        color: #6a859a;
        font-size: .88rem;
        margin-bottom: 24px;
    }
    .stat {
        background: #f0f6fd;
        border: 1px solid #bdd5e8;
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 14px;
    }
    .stat .label {
        font-size: .72rem;
        text-transform: uppercase;
        letter-spacing: .06em;
        color: #2f5b74;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .stat .value {
        font-size: 1.8rem;
        font-weight: 600;
        color: #0b2f40;
        font-family: 'SF Mono', 'Fira Code', monospace;
    }
    .stat.warn .value { color: #a15c00; }
    form { margin-top: 20px; }
    button {
        background: #1c6b8c;
        border: 1px solid #155a77;
        color: #fff;
        font-weight: 600;
        font-size: .95rem;
        padding: 12px 22px;
        border-radius: 30px;
        cursor: pointer;
        width: 100%;
        letter-spacing: .3px;
    }
    button:hover { background: #135f7e; }
    button:disabled { background: #b3c9d6; border-color: #9bb1c2; cursor: not-allowed; }
    .flash {
        margin-top: 20px;
        padding: 12px 16px;
        border-radius: 12px;
        font-size: .88rem;
        line-height: 1.5;
    }
    .flash.ok  { background: #e3f2e9; border: 1px solid #9ac7b0; color: #135c3b; }
    .flash.err { background: #ffe8e8; border: 1px solid #e6a9a9; color: #a12b2b; }
    .foot {
        margin-top: 26px;
        font-size: .75rem;
        color: #90a5b5;
        text-align: center;
    }
    code {
        background: #eef4fa;
        padding: 1px 6px;
        border-radius: 6px;
        font-size: .82em;
    }
</style>
</head>
<body>
<div class="box">
    <h1>🛠️ AES Vault — Admin</h1>
    <div class="sub">Signed in as <code><?php echo htmlspecialchars(ADMIN_USER, ENT_QUOTES, 'UTF-8'); ?></code></div>

    <?php if ($flash !== null): ?>
        <div class="flash <?php echo $flash['type'] === 'ok' ? 'ok' : 'err'; ?>">
            <?php echo htmlspecialchars($flash['msg'], ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <div class="stat">
        <div class="label">Total records in database</div>
        <div class="value"><?php echo number_format($totalCount); ?></div>
    </div>

    <div class="stat warn">
        <div class="label">Eligible for purge (&gt; 30 days old)</div>
        <div class="value"><?php echo number_format($purgeable); ?></div>
    </div>

    <form method="post" onsubmit="return confirm('Delete all records older than 30 days?');">
        <input type="hidden" name="action" value="purge">
        <button type="submit" <?php echo $purgeable === 0 ? 'disabled' : ''; ?>>
            🗑️ Purge records older than 30 days
        </button>
    </form>

    <div class="foot">
        Retention window: <?php echo (int)(PAYLOAD_RETENTION / 86400); ?> days ·
        Cutoff: <?php echo date('Y-m-d H:i:s', $cutoff); ?>
    </div>
</div>
</body>
</html>