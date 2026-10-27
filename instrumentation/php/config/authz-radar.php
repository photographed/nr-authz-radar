<?php

// Publish with: php artisan vendor:publish --tag=authz-radar-config
return [
    // Off: nothing is recorded and authz.owner only does the check (no telemetry)
    'enabled' => env('AUTHZ_RADAR_ENABLED', true),

    // Secret for HMAC pseudonyms (enduser.id, api.key_id). Without it no user ID is sent.
    // Use the same key in every service so the same user gets the same pseudonym.
    'hmac_key' => env('AUTHZ_RADAR_HMAC_KEY', ''),

    // 'minimal' = stage S2 (owner_match, decision, enduser.id). 'full' = stage S3.
    'attributes' => env('AUTHZ_RADAR_ATTRIBUTES', 'minimal'),

    // 'enforce' blocks a mismatch. 'observe' lets it through and records it, so detection D01
    // shows IDORs that really happen. Start existing apps on 'observe', then switch.
    'ownership_mode' => env('AUTHZ_RADAR_OWNERSHIP_MODE', 'enforce'),

    // Status for a blocked mismatch. 404 does not confirm that the resource exists.
    'deny_status' => 404,

    // Gate abilities that allow legitimate cross-owner access (admin, support). They are sent as
    // authz.required_scope so D01 can exclude them, e.g. ['view-any-order'].
    'bypass_abilities' => [],

    // Send denials to New Relic as errors. Off: the PHP agent has no "expected error" flag,
    // so denials would raise the error rate and Apdex alerts. Detections use attributes instead.
    'notice_denials' => false,

    // Write the fixed decision log line (shared/attribute-spec.md) for denials and for mismatches
    // that were let through. For high-security mode and the logs last mile (L04).
    'log_decisions' => env('AUTHZ_RADAR_LOG_DECISIONS', false),
    'log_channel' => env('AUTHZ_RADAR_LOG_CHANNEL'),

    // Add the RecordRequest middleware to the 'web' and 'api' groups automatically.
    'auto_middleware' => true,
];
