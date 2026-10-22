<?php declare(strict_types=1);

namespace StarlitDigital\aegis;

/** Reference adapter. No routes, autoload hooks, session access or filesystem serving. */
final class aegisStagingClient
{
    private const MAX_BYTES = 1048576;
    private const PURPOSE = 'account-import';
    private string $key;

    public function __construct(private readonly string $endpoint, string $keyFile)
    {
        if (!preg_match('~^http://127\.0\.0\.1:[0-9]{1,5}/v1/uploads$~D', $endpoint)) {
            throw new \InvalidArgumentException('aegis requires a fixed local endpoint');
        }
        $stat = lstat($keyFile);
        if ($stat === false || !is_file($keyFile) || is_link($keyFile) || ($stat['mode'] & 0077) !== 0 || $stat['size'] > 128) {
            throw new \InvalidArgumentException('aegis key must be a private regular file');
        }
        $hex = trim((string) file_get_contents($keyFile));
        if (!preg_match('/^[a-fA-F0-9]{64}$/D', $hex)) {
            throw new \InvalidArgumentException('Invalid aegis key');
        }
        $this->key = (string) hex2bin($hex);
    }

    /** Caller must derive subject from an authenticated session, never request input.
     * Store the returned ID with that subject and purpose in the application registry.
     * @return array{id:string, token:string, expires_at:int}
     */
    public function issueUpload(string $authenticatedSubject): array
    {
        $id = bin2hex(random_bytes(16));
        $expiry = time() + 30;
        return ['id' => $id, 'token' => $this->ticket($authenticatedSubject, $id, 'upload', $expiry), 'expires_at' => $expiry];
    }

    /** The caller must authorize this registered ID against the current user first.
     * Read grants remain on the server. Never send them to a browser or in a URL.
     */
    public function consume(string $authenticatedSubject, string $registeredId): string
    {
        $body = '';
        $digest = '';
        $ch = curl_init($this->endpoint);
        if ($ch === false) {
            throw new \RuntimeException('aegis connection unavailable');
        }
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $this->ticket($authenticatedSubject, $registeredId, 'read', time() + 30)],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROXY => '',
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP,
            CURLOPT_CONNECTTIMEOUT_MS => 1000,
            CURLOPT_TIMEOUT_MS => 15000,
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$digest): int {
                if (stripos($line, 'X-aegis-SHA256:') === 0) {
                    $digest = trim(substr($line, strlen('X-aegis-SHA256:')));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_BYTES) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        try {
            $ok = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            if ($ok === false || $status !== 200 || !preg_match('/^[a-f0-9]{64}$/D', $digest) || !hash_equals($digest, hash('sha256', $body))) {
                throw new \RuntimeException('aegis retrieval rejected');
            }
            return $body;
        } finally {
            unset($ch);
        }
    }

    private function ticket(string $subject, string $id, string $operation, int $expiry): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]{1,80}$/D', $subject) || !preg_match('/^[a-f0-9]{32}$/D', $id)) {
            throw new \InvalidArgumentException('Invalid staging identity');
        }
        $claims = ['purpose' => self::PURPOSE, 'aud' => 'aegis-staging-v1', 'id' => $id, 'sub' => $subject, 'op' => $operation, 'exp' => $expiry];
        $payload = self::base64url(json_encode($claims, JSON_THROW_ON_ERROR));
        return $payload . '.' . self::base64url(hash_hmac('sha256', $payload, $this->key, true));
    }

    private static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
