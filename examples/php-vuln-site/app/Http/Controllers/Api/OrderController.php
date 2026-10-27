<?php
declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Order;
use AuthzRadar\Laravel\ChecksOwnership;
use Illuminate\Http\JsonResponse;

/**
 * Same resource, now instrumented with nr-authz-radar. In OBSERVE mode the IDOR still happens
 * (the point of the demo) but ensureOwns() records resource.owner_match=false with decision=allow,
 * which is exactly what detection D01 looks for. Switch AUTHZ_RADAR_OWNERSHIP_MODE=enforce to block it.
 *
 * Local test fixture only. Never deploy.
 */
final class OrderController extends Controller
{
    use ChecksOwnership;

    public function show(string $id): JsonResponse
    {
        $order = Order::findOrFail($id);
        $this->ensureOwns($order);        // compares orders.user_id with the signed-in user
        return response()->json($order);
    }
}
