<?php
/**
 * encrypt.php - Single-file AES payload storage & retrieval endpoint
 * with embedded HTML/JS client (PHP 7 compatible)
 *
 * Storage: SQLite database (./payloads.sqlite):
 *   payloads (
 *       reference_id    TEXT PRIMARY KEY,
 *       encrypted       TEXT NOT NULL,
 *       validation_hash TEXT NOT NULL,
 *       created_at      INTEGER NOT NULL
 *   )
 *   rate_limits (
 *       bucket    TEXT NOT NULL,
 *       window_ts INTEGER NOT NULL,
 *       hits      INTEGER NOT NULL,
 *       PRIMARY KEY (bucket, window_ts)
 *   )
 *   _meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)
 *
 * ROUTES:
 *   POST  encrypt.php                         → store encrypted payload
 *   POST  encrypt.php?action=retrieve         → validate secret, return ciphertext, DELETE record
 *   GET   encrypt.php                         → serve the HTML/JS client page
 *
 * ONE-OFF SEMANTICS:
 *   - On successful secret validation, the ciphertext is returned to the client
 *     and the DB row is deleted within the same transaction.
 *   - On wrong secret, the record is preserved.
 *   - A second retrieve attempt for the same ID will return "not found".
 *
 * RETENTION:
 *   - Un-retrieved payloads older than 30 days are purged by a deterministic
 *     time-based GC (same pattern as the rate_limits cleanup).
 *   - GC runs at most every 5 minutes, tracked in the _meta table.
 *
 * SECURITY:
 *   - Client-side throttle (cosmetic)
 *   - Server-side fixed-window limiter persisted in SQLite, keyed by IP
 *   - Atomic counter increments (INSERT ... ON CONFLICT DO UPDATE)
 *   - 429 responses with Retry-After header
 *   - Rate-limit events logged to ./ratelimit.log
 */

// ===========================================================================
// CONFIG
// ===========================================================================
define('DB_PATH', __DIR__ . '/payloads.sqlite');
define('RATELIMIT_LOG', __DIR__ . '/ratelimit.log');
define('MAX_ENCRYPTED_B64', 16384);
define('MAX_JSON_BODY', 32768);
define('REF_ID_LEN', 32);
define('SECRET_MAX_LEN', 128);
define('MAX_PLAINTEXT_LEN', 1000);

// Rate limits: [maxHits, windowSecs]
define('RL_STORE_MAX',    20);
define('RL_STORE_WINDOW', 600);
define('RL_RETRIEVE_MAX', 30);
define('RL_RETRIEVE_WINDOW', 300);

// Retention policy
define('RL_RETENTION',      3600);          // 1 hour for rate-limit rows
define('PAYLOAD_RETENTION', 30 * 86400);    // 30 days for un-retrieved payloads
define('GC_INTERVAL',       300);           // 5 minutes between GC runs

// ===========================================================================
// HELPERS
// ===========================================================================
function read_json_body() {
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') return null;
    if (strlen($raw) > MAX_JSON_BODY) return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function respond($arr, $httpCode = 200, array $extraHeaders = []) {
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    foreach ($extraHeaders as $k => $v) {
        header($k . ': ' . $v);
    }
    echo json_encode($arr, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function is_valid_base64($s) {
    if (!is_string($s) || $s === '') return false;
    if (strlen($s) > MAX_ENCRYPTED_B64) return false;
    if (strlen($s) % 4 !== 0) return false;
    return base64_decode($s, true) !== false;
}

function is_valid_sha256_hex($s) {
    return is_string($s) && preg_match('/^[a-f0-9]{64}$/', $s) === 1;
}

function is_valid_reference_id($id) {
    return is_string($id) && preg_match('/^[a-f0-9]{' . REF_ID_LEN . '}$/', $id) === 1;
}

function compute_validation_hash($secret, $encryptedBase64) {
    return hash('sha256', $secret . $encryptedBase64);
}

function hash_equals_safe($known, $user) {
    if (!is_string($known) || !is_string($user)) return false;
    if (function_exists('hash_equals')) return hash_equals($known, $user);
    if (strlen($known) !== strlen($user)) return false;
    $res = 0;
    for ($i = 0; $i < strlen($known); $i++) {
        $res |= ord($known[$i]) ^ ord($user[$i]);
    }
    return $res === 0;
}

function client_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/**
 * Open (and initialize) the SQLite database.
 */
function db_open() {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    try {
        $isNew = !file_exists(DB_PATH);
        $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        if ($isNew) @chmod(DB_PATH, 0600);

        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA busy_timeout = 3000');

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS payloads (
                reference_id    TEXT PRIMARY KEY,
                encrypted       TEXT NOT NULL,
                validation_hash TEXT NOT NULL,
                created_at      INTEGER NOT NULL
            )'
        );

        // Index for the retention GC
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_payloads_created_at
                    ON payloads(created_at)');

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS rate_limits (
                bucket    TEXT    NOT NULL,
                window_ts INTEGER NOT NULL,
                hits      INTEGER NOT NULL,
                PRIMARY KEY (bucket, window_ts)
            )'
        );

        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS _meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )'
        );

        return $pdo;
    } catch (PDOException $e) {
        return null;
    }
}

/**
 * Fixed-window rate limiter stored in SQLite.
 */
function rate_limit_db(PDO $pdo, $key, $maxHits, $windowSecs) {
    $bucket   = hash('sha256', $key);
    $now      = time();
    $windowTs = intdiv($now, $windowSecs) * $windowSecs;
    $retryIn  = ($windowTs + $windowSecs) - $now;

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO rate_limits (bucket, window_ts, hits)
             VALUES (:b, :w, 1)
             ON CONFLICT(bucket, window_ts)
             DO UPDATE SET hits = hits + 1'
        );
        $stmt->execute([':b' => $bucket, ':w' => $windowTs]);

        $stmt = $pdo->prepare(
            'SELECT hits FROM rate_limits WHERE bucket = :b AND window_ts = :w'
        );
        $stmt->execute([':b' => $bucket, ':w' => $windowTs]);
        $hits = (int)$stmt->fetchColumn();

        return [$hits <= $maxHits, $retryIn, $hits];
    } catch (Throwable $e) {
        return [true, 0, 0];
    }
}

/**
 * Read the last-run timestamp for a named GC job.
 */
function gc_last_run(PDO $pdo, $name) {
    try {
        $stmt = $pdo->prepare('SELECT v FROM _meta WHERE k = :k');
        $stmt->execute([':k' => $name]);
        return (int)$stmt->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }
}

/**
 * Mark a GC job as having just run.
 */
function gc_touch(PDO $pdo, $name, $ts) {
    $pdo->prepare(
        'INSERT INTO _meta (k, v) VALUES (:k, :v)
         ON CONFLICT(k) DO UPDATE SET v = :v'
    )->execute([':k' => $name, ':v' => (string)$ts]);
}

/**
 * Deterministic time-based GC. Runs at most once every GC_INTERVAL seconds.
 * Two independent jobs share the same gate:
 *   - rate-limits: purge windows older than RL_RETENTION
 *   - payloads:    purge un-retrieved records older than PAYLOAD_RETENTION
 *
 * Both jobs are driven by a single _meta key ("gc_last") so the gate is
 * checked once per request.
 */
function db_gc(PDO $pdo) {
    try {
        $now  = time();
        $last = gc_last_run($pdo, 'gc_last');

        if ($last && ($now - $last) < GC_INTERVAL) {
            return;
        }

        // Mark as running before doing the work, to avoid thundering herd
        gc_touch($pdo, 'gc_last', $now);

        // Job 1: rate_limits — purge old windows
        try {
            $pdo->prepare('DELETE FROM rate_limits WHERE window_ts < :c')
                ->execute([':c' => $now - RL_RETENTION]);
        } catch (Throwable $e) {
            error_log('gc rate_limits failed: ' . $e->getMessage());
        }

        // Job 2: payloads — purge un-retrieved records older than 30 days
        try {
            $pdo->prepare('DELETE FROM payloads WHERE created_at < :c')
                ->execute([':c' => $now - PAYLOAD_RETENTION]);
        } catch (Throwable $e) {
            error_log('gc payloads failed: ' . $e->getMessage());
        }

    } catch (Throwable $e) {
        error_log('db_gc failed: ' . $e->getMessage());
    }
}

function log_rate_limit($ip, $action, $hits, $max) {
    $line = sprintf(
        "[%s] RATE_LIMIT ip=%s action=%s hits=%d max=%d ua=%s\n",
        date('c'),
        $ip,
        $action,
        $hits,
        $max,
        isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 160) : '-'
    );
    @file_put_contents(RATELIMIT_LOG, $line, FILE_APPEND | LOCK_EX);
}

// ===========================================================================
// ROUTING
// ===========================================================================
$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($method === 'OPTIONS') {
    http_response_code(204);
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Accept');
    exit;
}

if ($method === 'POST') {
    $cl = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
    if ($cl > MAX_JSON_BODY) {
        respond(['success' => false, 'error' => 'Request body too large'], 413);
    }
}

// ===========================================================================
// API: STORE
// ===========================================================================
if ($method === 'POST' && $action === '') {
    header('Content-Type: application/json; charset=utf-8');

    $pdo = db_open();
    if ($pdo === null) {
        respond(['success' => false, 'error' => 'Database unavailable'], 500);
    }

    $ip = client_ip();
    list($allowed, $retryIn, $hits) = rate_limit_db(
        $pdo, "store:$ip", RL_STORE_MAX, RL_STORE_WINDOW
    );
    if (!$allowed) {
        log_rate_limit($ip, 'store', $hits, RL_STORE_MAX);
        respond(
            ['success' => false, 'error' => 'Too many requests, slow down.'],
            429,
            ['Retry-After' => (string)max(1, $retryIn)]
        );
    }

    // Housekeeping: rate-limit + payload retention
    db_gc($pdo);

    $body = read_json_body();
    if ($body === null) {
        respond(['success' => false, 'error' => 'Invalid JSON body'], 400);
    }

    $encrypted = isset($body['encrypted'])       ? $body['encrypted']       : '';
    $hash      = isset($body['validation_hash']) ? $body['validation_hash'] : '';

    if (!is_valid_base64($encrypted)) {
        respond(['success' => false, 'error' => 'Invalid encrypted payload (base64)'], 400);
    }
    if (!is_valid_sha256_hex($hash)) {
        respond(['success' => false, 'error' => 'Invalid validation hash format'], 400);
    }

    $referenceId = '';
    $stmt = $pdo->prepare(
        'INSERT INTO payloads (reference_id, encrypted, validation_hash, created_at)
         VALUES (:rid, :enc, :hash, :ts)'
    );

    $stored = false;
    for ($attempt = 0; $attempt < 6; $attempt++) {
        $candidate = bin2hex(random_bytes(REF_ID_LEN / 2));
        try {
            $stmt->execute([
                ':rid'  => $candidate,
                ':enc'  => $encrypted,
                ':hash' => $hash,
                ':ts'   => time(),
            ]);
            $referenceId = $candidate;
            $stored = true;
            break;
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') continue;
            respond(['success' => false, 'error' => 'Database insert failed'], 500);
        }
    }

    if (!$stored) {
        respond(['success' => false, 'error' => 'Could not allocate reference ID'], 500);
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'example.com';
    $path   = strtok($_SERVER['REQUEST_URI'], '?');
    $url    = $scheme . '://' . $host . $path . '?id=' . $referenceId;

    respond([
        'success'      => true,
        'reference_id' => $referenceId,
        'url'          => $url,
        'one_off'      => true,
        'expires_in'   => PAYLOAD_RETENTION,   // seconds (informational)
    ]);
}

// ===========================================================================
// API: RETRIEVE (ONE-OFF)
// ===========================================================================
if ($method === 'POST' && $action === 'retrieve') {
    header('Content-Type: application/json; charset=utf-8');

    $pdo = db_open();
    if ($pdo === null) {
        respond(['success' => false, 'error' => 'Database unavailable'], 500);
    }

    $ip = client_ip();
    list($allowed, $retryIn, $hits) = rate_limit_db(
        $pdo, "retrieve:$ip", RL_RETRIEVE_MAX, RL_RETRIEVE_WINDOW
    );
    if (!$allowed) {
        log_rate_limit($ip, 'retrieve', $hits, RL_RETRIEVE_MAX);
        respond(
            ['success' => false, 'error' => 'Too many requests, slow down.'],
            429,
            ['Retry-After' => (string)max(1, $retryIn)]
        );
    }

    // Housekeeping: rate-limit + payload retention
    db_gc($pdo);

    $body = read_json_body();
    if ($body === null) {
        respond(['success' => false, 'error' => 'Invalid JSON body'], 400);
    }

    $referenceId = isset($body['reference_id']) ? $body['reference_id'] : '';
    $secret      = isset($body['secret'])       ? $body['secret']       : '';

    if (!is_valid_reference_id($referenceId)) {
        respond(['success' => false, 'error' => 'Invalid reference ID format'], 400);
    }
    if (!is_string($secret) || $secret === '' || strlen($secret) > SECRET_MAX_LEN) {
        respond(['success' => false, 'error' => 'Invalid secret'], 400);
    }

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare(
            'SELECT encrypted, validation_hash FROM payloads WHERE reference_id = :rid'
        );
        $stmt->execute([':rid' => $referenceId]);
        $row = $stmt->fetch();

        if (!$row) {
            $pdo->rollBack();
            respond(['success' => false, 'error' => 'Invalid reference ID or secret'], 401);
        }

        $storedEncrypted = $row['encrypted'];
        $storedHash      = $row['validation_hash'];

        $computedHash = compute_validation_hash($secret, $storedEncrypted);

        if (!hash_equals_safe($storedHash, $computedHash)) {
            $pdo->rollBack();
            respond(['success' => false, 'error' => 'Invalid reference ID or secret'], 401);
        }

        $del = $pdo->prepare('DELETE FROM payloads WHERE reference_id = :rid');
        $del->execute([':rid' => $referenceId]);

        if ($del->rowCount() !== 1) {
            $pdo->rollBack();
            respond(['success' => false, 'error' => 'Invalid reference ID or secret'], 401);
        }

        $pdo->commit();

        respond([
            'success'         => true,
            'reference_id'    => $referenceId,
            'encrypted'       => $storedEncrypted,
            'validation_hash' => $storedHash,
            'consumed'        => true,
        ]);

    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log('retrieve failed: ' . $e->getMessage());
        respond(['success' => false, 'error' => 'Database error during retrieval'], 500);
    }
}

// ===========================================================================
// Anything else → serve the HTML/JS client
// ===========================================================================
if ($method !== 'GET') {
    respond(['success' => false, 'error' => 'Unsupported request method'], 405);
}

// ---------------------------------------------------------------------------
// Security headers — ONLY for the HTML page (all API branches have exited
// via respond() by now, so this block is guaranteed to be the HTML branch).
// ---------------------------------------------------------------------------
header('Content-Security-Policy: '
     . "default-src 'none'; "
     . "script-src 'self' 'unsafe-inline'; "
     . "style-src 'self' 'unsafe-inline'; "
     . "connect-src 'self'; "
     . "img-src 'self' data:; "
     . "base-uri 'none'; "
     . "form-action 'none'; "
     . "frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AES client-side encrypt · one-off retrieval</title>
<style>
    * { box-sizing: border-box; font-family: system-ui, 'Segoe UI', Roboto, sans-serif; }
    body {
        background: #f5f7fb;
        display: flex; justify-content: center; align-items: flex-start;
        min-height: 100vh; margin: 0; padding: 24px 16px;
    }
    .card {
        background: #fff; border-radius: 28px;
        box-shadow: 0 20px 40px -12px rgba(0,20,30,.25);
        width: 100%; max-width: 720px;
        padding: 2rem 2rem 2.2rem;
    }
    h2 {
        margin: 0 0 .6rem; font-weight: 500; font-size: 1.7rem;
        letter-spacing: -.02em; color: #0b2b3b;
        display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    }
    h2 span {
        background: #e6edf4; border-radius: 40px;
        font-size: .8rem; font-weight: 500; padding: 4px 14px; color: #1e5f7a;
    }
    .subhead {
        color: #4a6679; font-size: .95rem;
        border-left: 4px solid #9dc6e0; padding-left: 14px;
        background: #f0f6fd; border-radius: 0 12px 12px 0;
        line-height: 1.45; margin: 0 0 1.6rem;
    }
    .oneoff-banner {
        margin: 0 0 1.6rem; padding: 14px 18px;
        background: linear-gradient(135deg, #fff4e0 0%, #ffe8cc 100%);
        border: 1.5px solid #e8b869;
        border-radius: 16px;
        color: #6b3d00; font-size: .9rem; line-height: 1.5;
        display: flex; gap: 12px; align-items: flex-start;
    }
    .oneoff-banner .icon {
        font-size: 1.5rem; line-height: 1; flex-shrink: 0;
    }
    .oneoff-banner strong { color: #8a4a00; }
    .tabs {
        display: flex; gap: 8px; margin-bottom: 1.4rem;
        border-bottom: 2px solid #e2ecf3; padding-bottom: 0;
    }
    .tab {
        background: none; border: none; padding: 12px 18px;
        font-size: .95rem; font-weight: 600; color: #6a859a;
        cursor: pointer; border-bottom: 3px solid transparent;
        margin-bottom: -2px; transition: .15s;
        border-radius: 8px 8px 0 0;
    }
    .tab:hover { color: #1c6b8c; background: #f0f6fd; }
    .tab.active { color: #1c6b8c; border-bottom-color: #1c6b8c; }
    label {
        font-weight: 500; font-size: .9rem; color: #1d3d4f;
        display: block; margin-bottom: 6px; letter-spacing: .3px;
    }
    textarea, input[type="text"] {
        width: 100%; padding: 14px 16px;
        border: 1.5px solid #cbdae6; border-radius: 18px;
        font-size: 1rem; background: #fbfdff; transition: .15s;
        font-family: 'SF Mono', 'Fira Code', monospace;
    }
    textarea { resize: vertical; min-height: 110px; max-height: 220px; }
    input[type="text"] { margin-bottom: 16px; }
    textarea:focus, input[type="text"]:focus {
        outline: none; border-color: #2e7ea3;
        box-shadow: 0 0 0 4px rgba(46,126,163,.15);
    }
    .charcount {
        font-size: .78rem; color: #6a859a;
        text-align: right; margin: 5px 0 16px;
    }
    .random-box {
        background: #eef4fa; border-radius: 18px; padding: 14px 18px;
        margin: 12px 0 10px; border: 1px solid #bdd5e8;
    }
    .random-label {
        font-size: .72rem; text-transform: uppercase;
        letter-spacing: .06em; color: #2f5b74; font-weight: 600; margin-bottom: 6px;
    }
    .random-value {
        font-family: 'SF Mono', 'Fira Code', monospace;
        font-size: 1rem; font-weight: 500; color: #0b2f40;
        background: #fff; padding: 10px 12px; border-radius: 12px;
        border: 1px solid #c2d6e6; word-break: break-all;
        margin-bottom: 10px;
    }
    .secret-actions {
        display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px;
    }
    .mini-btn {
        background: #dbeaf5; border: 1px solid #b0cde0;
        color: #155a77; font-size: .78rem; font-weight: 600;
        padding: 8px 14px; border-radius: 30px;
        cursor: pointer; letter-spacing: .04em;
        transition: .15s;
    }
    .mini-btn:hover { background: #c6dced; }
    .mini-btn.warn {
        background: #fff0d6; border-color: #e6cf9f; color: #805616;
    }
    .mini-btn.warn:hover { background: #fbe3b3; }
    button.primary {
        background: #1c6b8c; border: 1px solid #155a77; color: #fff;
        font-weight: 600; font-size: 1rem; padding: 14px 24px;
        border-radius: 40px; cursor: pointer; width: 100%;
        display: inline-flex; align-items: center; justify-content: center;
        gap: 8px; transition: .2s;
        box-shadow: 0 6px 12px -6px #0a2e3f40; letter-spacing: .3px;
        margin-top: 4px;
    }
    button.primary:hover:not(:disabled) {
        background: #135f7e; transform: scale(1.005);
        box-shadow: 0 10px 16px -8px #103a4e;
    }
    button.primary:disabled {
        background: #b3c9d6; border-color: #9bb1c2;
        cursor: not-allowed; opacity: .8; box-shadow: none;
    }
    button.primary.danger {
        background: #b04040; border-color: #8a3030;
    }
    button.primary.danger:hover:not(:disabled) {
        background: #953333;
        box-shadow: 0 10px 16px -8px #4a0d0d;
    }
    .status {
        margin-top: 1.4rem; font-size: .88rem; padding: 14px 18px;
        border-radius: 18px; background: #fff; border: 1px solid #d5e3ef;
        color: #1d455b; word-break: break-word; white-space: pre-wrap;
        max-height: 200px; overflow-y: auto;
        font-family: 'SF Mono', 'Fira Code', monospace;
    }
    .status.success { background: #e3f2e9; border-color: #9ac7b0; color: #135c3b; }
    .status.error   { background: #ffe8e8; border-color: #e6a9a9; color: #a12b2b; }
    .status.info    { background: #e5f0fa; border-color: #b8d4e9; color: #1b4e6e; }
    .status.warn    { background: #fff6e0; border-color: #e6cf9f; color: #6b4c11; }
    .output-box {
        margin-top: 16px; padding: 16px 18px;
        background: #f2f9ff; border-radius: 18px;
        border: 1px solid #b8d4e9; color: #0a2a3b;
        font-size: 1rem; line-height: 1.5;
        word-break: break-word; white-space: pre-wrap; display: none;
    }
    .output-box .label-small {
        font-size: .72rem; text-transform: uppercase;
        letter-spacing: .06em; color: #2f5b74;
        font-weight: 600; margin-bottom: 8px;
    }
    .output-box.frozen {
        background: #fffbe8;
        border-color: #e6d29a;
        color: #4a3a10;
    }
    .output-box.frozen .label-small { color: #7a5c14; }
    .output-box.destroyed {
        background: #f5e9e9;
        border-color: #d9b0b0;
        color: #5a2020;
    }
    .output-box.destroyed .label-small { color: #7a2a2a; }
    .hidden { display: none !important; }
    .hint {
        font-size: .78rem; color: #6a859a; margin-top: 4px;
        margin-bottom: 16px; line-height: 1.45;
    }
    .oneoff-tag {
        display: inline-block; background: #ffe8cc; color: #7a3d00;
        font-size: .68rem; font-weight: 700;
        padding: 2px 8px; border-radius: 10px;
        letter-spacing: .06em; text-transform: uppercase;
        margin-left: 6px; vertical-align: middle;
        border: 1px solid #e8b869;
    }
</style>
</head>
<body>
<div class="card">
    <h2>🔐 AES one-off vault <span>AES-GCM · SHA-256 · SQLite</span></h2>
    <div class="subhead">
        Encrypt in the browser, store the ciphertext in SQLite, and retrieve it exactly once.
        The server never sees the plaintext or the secret's raw form.
    </div>

    <div class="oneoff-banner">
        <div class="icon">⚠️</div>
        <div>
            <strong>One-off URLs only.</strong> The generated URL can be used <strong>once</strong>.
            Upon successful retrieval and decryption, the stored record is <strong>permanently deleted</strong> from the server.
            A wrong secret does <em>not</em> consume the record, so you may retry.
            Un-retrieved records are automatically purged after <strong>30 days</strong>.
        </div>
    </div>

    <div class="tabs">
        <button class="tab active" data-tab="encrypt">🔒 Encrypt &amp; store</button>
        <button class="tab" data-tab="retrieve">🔓 Retrieve &amp; decrypt <span class="oneoff-tag">one-off</span></button>
    </div>

    <!-- ===================== ENCRYPT PANEL ===================== -->
    <section id="panel-encrypt">
        <label for="plainText">Your message <span style="font-weight:400;color:#527a91;">(max 1000 chars)</span></label>
        <textarea id="plainText" maxlength="1000" placeholder="Type anything here...">Hello, secret world! 🌍</textarea>
        <div class="charcount"><span id="charCounter">0</span> / 1000</div>

        <div class="random-box">
            <div class="random-label">🔑 Secret for the NEXT encryption (AES key material)</div>
            <div class="random-value" id="randomStringDisplay">—</div>
            <div class="secret-actions">
                <button class="mini-btn" id="copySecretBtn" type="button">📋 Copy secret</button>
                <button class="mini-btn warn" id="newSecretBtn" type="button">🔄 Generate new secret</button>
            </div>
        </div>
        <div class="hint">
            ⚠️ The secret shown above is the one that will be used when you click <em>Encrypt &amp; store</em>.
            Copy it and keep it safe — it is required to decrypt later and cannot be recovered.
        </div>

        <button class="primary" id="encryptAndSendBtn">🔒 Encrypt &amp; store with this secret</button>

        <div id="encryptStatus" class="status info">Ready. Copy the secret, then click encrypt.</div>

        <div id="storeResultBox" class="output-box">
            <div class="label-small">✅ Stored — save these for later (⚠️ URL is one-off · expires in 30 days)</div>
            <div id="storeResultContent"></div>
        </div>
    </section>

    <!-- ===================== RETRIEVE PANEL ===================== -->
    <section id="panel-retrieve" class="hidden">
        <label for="referenceId">Reference ID</label>
        <input type="text" id="referenceId" placeholder="e.g. 9f3a... (32 hex chars)" autocomplete="off" spellcheck="false">

        <label for="secretInput">Secret (random alphanumeric string)</label>
        <input type="text" id="secretInput" placeholder="The secret you saved when encrypting" autocomplete="off" spellcheck="false">

        <button class="primary danger" id="retrieveBtn">🔥 Retrieve, decrypt &amp; destroy</button>

        <div id="retrieveStatus" class="status info">Ready. Enter reference ID and secret, then click retrieve.</div>

        <div id="plaintextBox" class="output-box">
            <div class="label-small">🔓 Decrypted message</div>
            <div id="plaintextContent"></div>
        </div>

        <div id="destroyedBox" class="output-box destroyed">
            <div class="label-small">🔥 Record destroyed</div>
            <div id="destroyedContent">The payload has been permanently deleted from the server. This reference ID can no longer be used.</div>
        </div>
    </section>
</div>

<script>
(function () {
    'use strict';

    // =====================================================================
    // DOM
    // =====================================================================
    const $ = (id) => document.getElementById(id);

    const tabButtons = document.querySelectorAll('.tab');
    const panelEncrypt = $('panel-encrypt');
    const panelRetrieve = $('panel-retrieve');

    // Encrypt panel
    const textarea        = $('plainText');
    const charCounter     = $('charCounter');
    const randomDisplay   = $('randomStringDisplay');
    const copySecretBtn   = $('copySecretBtn');
    const newSecretBtn    = $('newSecretBtn');
    const encryptBtn      = $('encryptAndSendBtn');
    const encryptStatus   = $('encryptStatus');
    const storeResultBox  = $('storeResultBox');
    const storeResultCont = $('storeResultContent');

    // Retrieve panel
    const referenceIdInput = $('referenceId');
    const secretInput      = $('secretInput');
    const retrieveBtn      = $('retrieveBtn');
    const retrieveStatus   = $('retrieveStatus');
    const plaintextBox     = $('plaintextBox');
    const plaintextContent = $('plaintextContent');
    const destroyedBox     = $('destroyedBox');

    // Endpoints
    const ENDPOINT_STORE    = window.location.pathname;
    const ENDPOINT_RETRIEVE = window.location.pathname + '?action=retrieve';

    // =====================================================================
    // CLIENT-SIDE THROTTLE
    // =====================================================================
    const MIN_SUBMIT_INTERVAL_MS = 2500;
    let lastSubmitAtStore    = 0;
    let lastSubmitAtRetrieve = 0;
    let submitInFlight       = false;

    async function guardedSubmit(kind, statusEl, action) {
        const now = Date.now();
        const last = (kind === 'store') ? lastSubmitAtStore : lastSubmitAtRetrieve;

        if (submitInFlight) {
            setStatus(statusEl, '⏳ A request is already in progress. Please wait…', 'warn');
            return false;
        }
        const elapsed = now - last;
        if (elapsed < MIN_SUBMIT_INTERVAL_MS) {
            const wait = Math.ceil((MIN_SUBMIT_INTERVAL_MS - elapsed) / 1000);
            setStatus(statusEl,
                '⏳ Slow down a moment — please wait ' + wait + 's before submitting again.',
                'warn');
            return false;
        }

        if (kind === 'store') lastSubmitAtStore = now;
        else                  lastSubmitAtRetrieve = now;

        submitInFlight = true;
        try {
            await action();
            return true;
        } finally {
            submitInFlight = false;
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================
    function setStatus(el, msg, type) {
        el.textContent = msg;
        el.className = 'status ' + (type || 'info');
    }

    function generateRandomAlphanumeric(length) {
        length = length || 32;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const bytes = new Uint8Array(length);
        crypto.getRandomValues(bytes);
        let out = '';
        for (let i = 0; i < length; i++) out += chars[bytes[i] % chars.length];
        return out;
    }

    function base64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToBase64(bytes) {
        let bin = '';
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return btoa(bin);
    }

    async function deriveAESKey(secretString, usages) {
        const secretBytes = new TextEncoder().encode(secretString);
        const hashBuffer  = await crypto.subtle.digest('SHA-256', secretBytes);
        return crypto.subtle.importKey(
            'raw', hashBuffer,
            { name: 'AES-GCM', length: 256 },
            false,
            usages
        );
    }

    async function aesEncrypt(plainText, secretString) {
        const key = await deriveAESKey(secretString, ['encrypt']);
        const iv  = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(plainText);
        const enc  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
        const cipherBytes = new Uint8Array(enc);
        const combined = new Uint8Array(iv.length + cipherBytes.length);
        combined.set(iv, 0);
        combined.set(cipherBytes, iv.length);
        return bytesToBase64(combined);
    }

    async function aesDecrypt(encryptedBase64, secretString) {
        const raw = base64ToBytes(encryptedBase64);
        const IV_LEN  = 12;
        const TAG_LEN = 16;
        if (raw.length < IV_LEN + TAG_LEN) {
            throw new Error('Encrypted payload is too short / malformed.');
        }
        const iv         = raw.slice(0, IV_LEN);
        const cipherAndTag = raw.slice(IV_LEN);
        const tag        = cipherAndTag.slice(-TAG_LEN);
        const ciphertext = cipherAndTag.slice(0, -TAG_LEN);

        const combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext, 0);
        combined.set(tag, ciphertext.length);

        const key = await deriveAESKey(secretString, ['decrypt']);
        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            combined
        );
        return new TextDecoder().decode(plainBuf);
    }

    async function sha256Hex(str) {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    async function readJsonResponse(resp) {
        const raw = await resp.text();
        let data;
        try { data = JSON.parse(raw); }
        catch (e) { throw new Error('Server returned non-JSON: ' + raw.slice(0, 200)); }

        if (resp.status === 429) {
            const retry = resp.headers.get('Retry-After');
            const suffix = retry ? ' (retry in ~' + retry + 's)' : '';
            throw new Error((data && data.error ? data.error : 'Rate limited') + suffix);
        }
        return data;
    }

    // =====================================================================
    // Tabs
    // =====================================================================
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (btn.dataset.tab === 'encrypt') {
                panelEncrypt.classList.remove('hidden');
                panelRetrieve.classList.add('hidden');
            } else {
                panelRetrieve.classList.remove('hidden');
                panelEncrypt.classList.add('hidden');
            }
        });
    });

    // =====================================================================
    // Character counter
    // =====================================================================
    function updateCharCounter() {
        charCounter.textContent = textarea.value.length;
    }
    textarea.addEventListener('input', updateCharCounter);
    updateCharCounter();

    // =====================================================================
    // SECRET MANAGEMENT
    // =====================================================================
    let currentSecret = generateRandomAlphanumeric(32);
    randomDisplay.textContent = currentSecret;

    function refreshSecretDisplay() {
        randomDisplay.textContent = currentSecret;
    }

    function setNewSecret() {
        currentSecret = generateRandomAlphanumeric(32);
        refreshSecretDisplay();
    }

    newSecretBtn.addEventListener('click', () => {
        setNewSecret();
        storeResultBox.style.display = 'none';
        setStatus(encryptStatus, '🔄 New secret generated. Copy it before encrypting.', 'info');
    });

    copySecretBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(currentSecret);
            const original = copySecretBtn.textContent;
            copySecretBtn.textContent = '✅ Copied!';
            setTimeout(() => { copySecretBtn.textContent = original; }, 1400);
        } catch (e) {
            setStatus(encryptStatus, '⚠️ Clipboard copy failed — please copy the secret manually.', 'error');
        }
    });

    // =====================================================================
    // ENCRYPT & STORE
    // =====================================================================
    encryptBtn.addEventListener('click', () => {
        guardedSubmit('store', encryptStatus, async () => {
            const plainText = textarea.value;
            if (plainText.length > 1000) {
                setStatus(encryptStatus, '❌ Input exceeds 1000 characters.', 'error');
                return;
            }
            if (plainText.trim() === '') {
                setStatus(encryptStatus, '⚠️ Input is empty. Nothing to encrypt.', 'error');
                return;
            }

            const secretUsed = currentSecret;

            encryptBtn.disabled = true;
            storeResultBox.style.display = 'none';
            storeResultBox.classList.remove('frozen');

            setStatus(encryptStatus,
                '⏳ Encrypting with the displayed secret…\n(Secret first 8 chars: ' + secretUsed.slice(0, 8) + '…)',
                'info');

            try {
                const encryptedBase64 = await aesEncrypt(plainText, secretUsed);
                const validationHash = await sha256Hex(secretUsed + encryptedBase64);

                setStatus(encryptStatus,
                    '📤 Encrypted locally. Sending to server…\nHash: ' + validationHash.slice(0, 32) + '…',
                    'info');

                const resp = await fetch(ENDPOINT_STORE, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({
                        encrypted: encryptedBase64,
                        validation_hash: validationHash
                    })
                });

                const data = await readJsonResponse(resp);
                if (!resp.ok || !data.success) {
                    throw new Error(data && data.error ? data.error : ('HTTP ' + resp.status));
                }

                const refId = data.reference_id;
                const url   = data.url || (window.location.origin + window.location.pathname + '?id=' + refId);

                // Clear previous content safely
                storeResultCont.textContent = '';

                // Reference ID line
                storeResultCont.appendChild(
                    document.createTextNode('Reference ID: ' + refId + '\n')
                );
                storeResultCont.appendChild(
                    document.createTextNode('Secret:       ' + secretUsed + '\n')
                );

                // URL line with clickable link
                storeResultCont.appendChild(document.createTextNode('URL:          '));
                const link = document.createElement('a');
                link.href = url;
                link.textContent = url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.style.wordBreak = 'break-all';
                link.style.color = '#1c6b8c';
                storeResultCont.appendChild(link);
                storeResultCont.appendChild(document.createTextNode('\n\n'));

                // Warning block
                storeResultCont.appendChild(document.createTextNode(
                    '🔥 This URL is ONE-OFF. It can be used only once.\n' +
                    '   Upon successful retrieval, the server deletes the record permanently.\n' +
                    '   A wrong secret does NOT consume the record — you may retry.\n' +
                    '⏳ Un-retrieved records are automatically purged after 30 days.\n\n' +
                    '⚠️ Keep the Reference ID AND this exact Secret safe. The secret cannot be recovered.'
                ));
                storeResultBox.classList.add('frozen');
                storeResultBox.style.display = 'block';

                referenceIdInput.value = refId;
                secretInput.value = secretUsed;

                setStatus(encryptStatus,
                    '✅ Stored in SQLite (HTTP ' + resp.status + ').\n' +
                    'Reference ID: ' + refId + '\n' +
                    '🔥 One-off URL — the record will be destroyed on the first successful retrieval.\n' +
                    '⏳ Auto-expires in 30 days if unused.\n' +
                    'The Secret that was used is shown in the yellow box below — copy it now.',
                    'success');

                setNewSecret();

            } catch (err) {
                console.error(err);
                setStatus(encryptStatus,
                    '❌ Error: ' + (err.message || err) + '\n\n' +
                    'Note: the secret displayed above is still the one that would be used on retry.',
                    'error');
            } finally {
                encryptBtn.disabled = false;
            }
        });
    });

    // =====================================================================
    // RETRIEVE & DECRYPT (ONE-OFF)
    // =====================================================================
    retrieveBtn.addEventListener('click', () => {
        guardedSubmit('retrieve', retrieveStatus, async () => {
            plaintextBox.style.display = 'none';
            destroyedBox.style.display = 'none';
            plaintextContent.textContent = '';

            const referenceId = referenceIdInput.value.trim();
            const secret      = secretInput.value;

            if (!/^[a-f0-9]{32}$/.test(referenceId)) {
                setStatus(retrieveStatus, '❌ Reference ID must be 32 lowercase hex characters.', 'error');
                return;
            }
            if (!secret || secret.length > 128) {
                setStatus(retrieveStatus, '❌ Please enter a valid secret.', 'error');
                return;
            }

            retrieveBtn.disabled = true;
            setStatus(retrieveStatus,
                '📡 Requesting payload from server…\n(If the secret is correct, the record will be destroyed.)',
                'info');

            try {
                const resp = await fetch(ENDPOINT_RETRIEVE, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({ reference_id: referenceId, secret: secret })
                });

                const data = await readJsonResponse(resp);
                if (!resp.ok || !data.success) {
                    throw new Error(data && data.error ? data.error : ('HTTP ' + resp.status));
                }

                const encryptedB64 = data.encrypted;
                const storedHash   = data.validation_hash;

                if (!encryptedB64 || typeof encryptedB64 !== 'string') {
                    throw new Error('Server did not return an encrypted payload.');
                }

                setStatus(retrieveStatus, '🔐 Server validated and deleted the record. Verifying hash locally…', 'info');
                const localHash = await sha256Hex(secret + encryptedB64);
                if (localHash !== storedHash) {
                    throw new Error('Local hash check failed — payload may be tampered with.');
                }

                setStatus(retrieveStatus, '🔓 Decrypting locally…', 'info');
                const plaintext = await aesDecrypt(encryptedB64, secret);

                plaintextContent.textContent = plaintext;
                plaintextBox.style.display = 'block';

                destroyedBox.style.display = 'block';

                setStatus(retrieveStatus,
                    '✅ Decryption successful.\n' +
                    'Reference: ' + referenceId + '\n' +
                    '🔥 The record has been DELETED from the server.\n' +
                    '   This reference ID is now permanently unusable.',
                    'success');

                secretInput.value = '';

            } catch (err) {
                console.error(err);
                setStatus(retrieveStatus,
                    '❌ Retrieval/decryption failed:\n' + (err.message || err) + '\n\n' +
                    'Tip: verify the reference ID and that the secret matches the one used at encryption time.\n' +
                    'A wrong secret does NOT consume the record — you may retry.\n' +
                    'Records not retrieved within 30 days are purged automatically.',
                    'error');
            } finally {
                retrieveBtn.disabled = false;
            }
        });
    });

    // Enter key in either retrieve input triggers retrieval
    [referenceIdInput, secretInput].forEach(el => {
        el.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                retrieveBtn.click();
            }
        });
    });

    // Prefill reference ID from ?id= URL parameter
    try {
        const params = new URLSearchParams(window.location.search);
        const idFromUrl = params.get('id');
        if (idFromUrl && /^[a-f0-9]{32}$/.test(idFromUrl)) {
            referenceIdInput.value = idFromUrl;
            tabButtons.forEach(b => b.classList.remove('active'));
            document.querySelector('.tab[data-tab="retrieve"]').classList.add('active');
            panelRetrieve.classList.remove('hidden');
            panelEncrypt.classList.add('hidden');
        }
    } catch (e) { /* ignore */ }

})();
</script>
</body>
</html>
<?php
// End of file — nothing else to output.