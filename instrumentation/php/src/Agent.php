<?php
declare(strict_types=1);

namespace AuthzRadar;

/** What the telemetry needs from the New Relic agent. Replace it in tests. */
interface Agent
{
    public function attribute(string $key, bool|int|float|string $value): void;

    public function userId(string $pseudonym): void;

    public function noticeError(\Throwable $error): void;
}
