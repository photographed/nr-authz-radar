<?php
declare(strict_types=1);

namespace AuthzRadar;

/**
 * Calls the New Relic PHP agent (a C extension). Every call is skipped when the function is
 * missing, so the application works the same without the agent.
 *
 * Function names checked against the agent source (newrelic-php-agent 12.12.0, agent/php_api.c):
 * newrelic_add_custom_parameter, newrelic_set_user_id (agent 10.12+), newrelic_notice_error.
 * The PHP agent has no "expected error" flag, so denials are not sent as errors by default
 * (see Telemetry::$noticeDenials).
 */
final class NewRelicAgent implements Agent
{
    public function attribute(string $key, bool|int|float|string $value): void
    {
        if (\function_exists('newrelic_add_custom_parameter')) {
            \newrelic_add_custom_parameter($key, $value);
        }
    }

    public function userId(string $pseudonym): void
    {
        if (\function_exists('newrelic_set_user_id')) {
            \newrelic_set_user_id($pseudonym);
        } elseif (\function_exists('newrelic_add_custom_parameter')) {
            \newrelic_add_custom_parameter('enduser.id', $pseudonym); // agents older than 10.12
        }
    }

    public function noticeError(\Throwable $error): void
    {
        if (\function_exists('newrelic_notice_error')) {
            \newrelic_notice_error($error);
        }
    }
}
