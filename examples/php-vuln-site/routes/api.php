<?php
declare(strict_types=1);

use App\Http\Controllers\Api\AdminController;
use App\Http\Controllers\Api\OrderController;
use App\Http\Controllers\Api\RawOrderController;
use Illuminate\Support\Facades\Route;

// All endpoints require an api_token (query string or bearer). Authentication is fine here;
// the deliberate bugs are in authorization. Local test fixture only.
Route::middleware('auth')->group(function () {
    // Instrumented (nr-authz-radar). D01 lights up in observe mode; enforce blocks the IDOR.
    Route::get('/orders/{id}', [OrderController::class, 'show']);
    Route::patch('/orders/{id}/ship', [AdminController::class, 'markShipped']); // BFLA: no admin check

    // Not instrumented: the same IDOR + SQLi, invisible to New Relic (the "before").
    Route::get('/raw/orders/{id}', [RawOrderController::class, 'show']);
    Route::get('/raw/orders', [RawOrderController::class, 'search']);
});
