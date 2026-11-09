<?php
// Tidemark admin UI backend: serves index.html and signs admin API calls. PHP 8+, no extensions.
//   TIDEMARK_ACCESS_KEY=... TIDEMARK_SECRET_KEY=... php -S 127.0.0.1:9080 server.php

$endpoint = rtrim(getenv('TIDEMARK_ENDPOINT') ?: 'http://127.0.0.1:9000', '/');
$accessKey = getenv('TIDEMARK_ACCESS_KEY') ?: (getenv('TIDEMARK_ACCESS_KEY_ID') ?: '');
$secretKey = getenv('TIDEMARK_SECRET_KEY') ?: (getenv('TIDEMARK_SECRET_ACCESS_KEY') ?: '');
$region = getenv('TIDEMARK_REGION') ?: 'us-east-1';
$host = $_SERVER['SERVER_NAME'] . ':' . $_SERVER['SERVER_PORT'];

function out(int $status, string $body, string $type = 'application/json; charset=utf-8'): void
{
    http_response_code($status);
    header("Content-Type: $type");
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    echo $body;
    exit;
}

function fail(int $status, string $message): void
{
    out($status, json_encode(['error' => $message]));
}

function q(string $s): string
{
    return str_replace('%7E', '~', rawurlencode($s));
}

if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) fail(403, 'Local access only');
if (($_SERVER['HTTP_HOST'] ?? '') !== $host) fail(403, 'Forbidden host');
if ($accessKey === '' || $secretKey === '') fail(500, 'Set TIDEMARK_ACCESS_KEY and TIDEMARK_SECRET_KEY.');

$method = $_SERVER['REQUEST_METHOD'];
$url = parse_url($_SERVER['REQUEST_URI']);
$reqPath = $url['path'] ?? '/';

if ($method === 'GET' && ($reqPath === '/' || $reqPath === '/index.html')) {
    out(200, file_get_contents(__DIR__ . '/index.html'), 'text/html; charset=utf-8');
}
if (!str_starts_with($reqPath, '/api/') || ($_SERVER['HTTP_X_TIDEMARK_UI'] ?? '') !== '1') fail(404, 'Not found');
if (isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== "http://$host") fail(403, 'Forbidden origin');

$path = substr($reqPath, 5);
$read = '#^(info|whoami|buckets|users|access-keys|trash)$#';
$write = '#^(trash/restore|users/[^/]+/(enable|disable)|access-keys/[^/]+/(activate|deactivate))$#';
if (!in_array($method, ['GET', 'POST'], true) || !preg_match($method === 'GET' ? $read : $write, $path)) fail(404, 'Not found');

$query = [];
if ($path === 'trash') {
    parse_str($url['query'] ?? '', $in);
    foreach (['limit', 'bucket', 'prefix', 'cursor'] as $k) {
        if (isset($in[$k]) && is_string($in[$k])) $query[$k] = $in[$k];
    }
    ksort($query);
}
$body = '';
if ($path === 'trash/restore') {
    $body = file_get_contents('php://input', false, null, 0, 64 * 1024);
}

$base = parse_url($endpoint);
$hostHeader = $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');
$fullPath = rtrim($base['path'] ?? '', '/') . '/_tidemark/v1/' . implode('/', array_map(fn($p) => q(rawurldecode($p)), explode('/', $path)));
$qs = implode('&', array_map(fn($k, $v) => q($k) . '=' . q($v), array_keys($query), $query));

$now = gmdate('Ymd\THis\Z');
$date = substr($now, 0, 8);
$bodySha = hash('sha256', $body);
$headers = ['host' => $hostHeader, 'x-amz-content-sha256' => $bodySha, 'x-amz-date' => $now];
if ($body !== '') $headers['content-type'] = 'application/json';
ksort($headers);
$names = implode(';', array_keys($headers));
$canonical = implode("\n", [
    $method, $fullPath, $qs,
    implode('', array_map(fn($k, $v) => "$k:$v\n", array_keys($headers), $headers)),
    $names, $bodySha,
]);
$scope = "$date/$region/s3/aws4_request";
$toSign = implode("\n", ['AWS4-HMAC-SHA256', $now, $scope, hash('sha256', $canonical)]);
$key = 'AWS4' . $secretKey;
foreach ([$date, $region, 's3', 'aws4_request'] as $part) $key = hash_hmac('sha256', $part, $key, true);
$headers['authorization'] = "AWS4-HMAC-SHA256 Credential=$accessKey/$scope, SignedHeaders=$names, Signature=" . hash_hmac('sha256', $toSign, $key);

$target = $base['scheme'] . '://' . $hostHeader . $fullPath . ($qs !== '' ? "?$qs" : '');
$ctx = stream_context_create(['http' => [
    'method' => $method,
    'header' => implode("\r\n", array_map(fn($k, $v) => "$k: $v", array_keys($headers), $headers)),
    'content' => $body,
    'ignore_errors' => true,
    'timeout' => 15,
]]);
$resp = @file_get_contents($target, false, $ctx);
if ($resp === false) fail(502, "Cannot reach Tidemark at $endpoint");
preg_match('#^HTTP/\S+ (\d{3})#', $http_response_header[0] ?? '', $m);
out((int) ($m[1] ?? 502), $resp !== '' ? $resp : '{}');
