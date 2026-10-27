<?php
declare(strict_types=1);

namespace AuthzRadar;

/** Keyed HMAC so raw IDs never leave the app. Same output as the Java / Python / Node libraries. */
final class Pseudonymizer
{
    public function __construct(private readonly string $key)
    {
    }

    /** 'u_' + 16 hex chars, or null without a key (a plain hash of a user ID can be brute-forced). */
    public function user(int|string|null $userId): ?string
    {
        return self::pseudonym($userId, $this->key, 'u_', 16);
    }

    /** 'k_' + 8 hex chars, for api.key_id. */
    public function apiKey(?string $apiKey): ?string
    {
        return self::pseudonym($apiKey, $this->key, 'k_', 8);
    }

    public static function pseudonym(int|string|null $value, string $key, string $prefix = 'u_', int $length = 16): ?string
    {
        if (trim($key) === '' || $value === null || (string) $value === '') {
            return null;
        }
        return $prefix . substr(hash_hmac('sha256', (string) $value, $key), 0, $length);
    }
}
