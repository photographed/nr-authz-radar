<?php
declare(strict_types=1);

namespace Database\Seeders;

use App\Models\Order;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        // Fixed tokens so the local check script can authenticate as each user.
        $alice = User::create(['name' => 'Alice', 'email' => 'alice@example.test', 'password' => Hash::make('password'), 'api_token' => 'token-alice', 'is_admin' => false]);
        $bob = User::create(['name' => 'Bob', 'email' => 'bob@example.test', 'password' => Hash::make('password'), 'api_token' => 'token-bob', 'is_admin' => false]);
        User::create(['name' => 'Admin', 'email' => 'admin@example.test', 'password' => Hash::make('password'), 'api_token' => 'token-admin', 'is_admin' => true]);

        Order::create(['user_id' => $alice->id, 'item' => 'Keyboard', 'amount' => 4000, 'status' => 'placed']);
        Order::create(['user_id' => $alice->id, 'item' => 'Mouse', 'amount' => 2000, 'status' => 'placed']);
        Order::create(['user_id' => $bob->id, 'item' => 'Monitor', 'amount' => 30000, 'status' => 'placed']);
    }
}
