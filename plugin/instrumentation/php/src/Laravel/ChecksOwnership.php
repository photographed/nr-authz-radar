<?php
declare(strict_types=1);

namespace AuthzRadar\Laravel;

use AuthzRadar\OwnershipError;
use AuthzRadar\Telemetry;

/**
 * For controllers, GraphQL resolvers and jobs that load a resource by a client-supplied ID:
 *
 *   $order = Order::findOrFail($id);
 *   $this->ensureOwns($order);                  // compares $order->user_id with auth()->id()
 */
trait ChecksOwnership
{
    protected function ensureOwns(object $resource, string $column = 'user_id', ?string $type = null): void
    {
        $user = auth()->user();
        $type ??= strtolower(class_basename($resource));
        try {
            app(Telemetry::class)->checkOwnership(data_get($resource, $column), $user?->getAuthIdentifier(), $type, CheckOwnership::bypass($user));
        } catch (OwnershipError) {
            abort((int) config('authz-radar.deny_status', 404));
        }
    }
}
