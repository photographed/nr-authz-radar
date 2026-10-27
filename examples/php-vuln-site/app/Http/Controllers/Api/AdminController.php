<?php
declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Order;
use Illuminate\Http\JsonResponse;

/**
 * BFLA (CWE-285, API5): an admin-only action with no role check, so any authenticated user can
 * change any order's status. Mounted under 'auth' only, so the caller is known but not authorized.
 *
 * Local test fixture only. Never deploy.
 */
final class AdminController extends Controller
{
    public function markShipped(string $id): JsonResponse
    {
        $order = Order::findOrFail($id);
        $order->update(['status' => 'shipped']);   // missing: is the caller an admin?
        return response()->json($order);
    }
}
