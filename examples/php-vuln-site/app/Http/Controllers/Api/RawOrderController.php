<?php
declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Order;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * DELIBERATELY VULNERABLE, and NOT instrumented. This is the "before" state: the authorization
 * holes are real, but because the app sends no authz telemetry, New Relic sees only 200 OK and
 * cannot tell these apart from normal traffic. Compare with the instrumented controller.
 *
 * Local test fixture only. Never deploy. See examples/php-vuln-site/README.md.
 */
final class RawOrderController extends Controller
{
    // IDOR / BOLA (CWE-639): returns any order by id, no owner check.
    public function show(string $id): JsonResponse
    {
        return response()->json(Order::findOrFail($id));
    }

    // SQL injection (CWE-89): the query string is concatenated straight into SQL.
    public function search(Request $request): JsonResponse
    {
        $q = (string) $request->query('item', '');
        $rows = DB::select("SELECT id, item, amount FROM orders WHERE item LIKE '%" . $q . "%'");
        return response()->json($rows);
    }
}
