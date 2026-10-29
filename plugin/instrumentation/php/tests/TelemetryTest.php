<?php
declare(strict_types=1);

// Run: php tests/TelemetryTest.php   (no Composer, no agent: the agent is replaced by a recorder)
require __DIR__ . '/../autoload.php';

use AuthzRadar\Agent;
use AuthzRadar\DecisionLog;
use AuthzRadar\OwnershipError;
use AuthzRadar\Pseudonymizer;
use AuthzRadar\Telemetry;

final class Recorder implements Agent
{
    public array $attrs = [];
    public ?string $user = null;
    public int $errors = 0;

    public function attribute(string $key, bool|int|float|string $value): void { $this->attrs[$key] = $value; }
    public function userId(string $pseudonym): void { $this->user = $pseudonym; }
    public function noticeError(\Throwable $error): void { $this->errors++; }
}

$failures = 0;
function check(bool $ok, string $name): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . PHP_EOL;
    $failures += $ok ? 0 : 1;
}

function make(string $attrs = Telemetry::MINIMAL, string $mode = Telemetry::ENFORCE, bool $notice = false, ?array &$logs = null): array
{
    $rec = new Recorder();
    $logs = [];
    $sink = static function (string $line) use (&$logs): void { $logs[] = $line; };
    return [new Telemetry($rec, new Pseudonymizer('k'), $attrs, $mode, $notice, $sink), $rec];
}

[$t, $r] = make();
check($t->checkOwnership(7, '7', 'order') === true && $r->attrs === ['resource.owner_match' => true, 'authz.decision' => 'allow'],
    'match: owner_match=true, allow, MINIMAL sends nothing else');

[$t, $r] = make(logs: $logs);
try { $t->checkOwnership(7, 8, 'order'); $thrown = false; } catch (OwnershipError) { $thrown = true; }
check($thrown && $r->attrs['authz.decision'] === 'deny' && $r->attrs['resource.owner_match'] === false, 'enforce: mismatch throws and records deny');
check($r->errors === 0, 'enforce: denial is not sent as an error by default (no expected flag in PHP)');
check($logs === ['authz-radar decision=deny owner_match=false reason=owner_mismatch resource.type=order api.operation=-'], 'enforce: one deny log line');

[$t, $r] = make(notice: true);
try { $t->checkOwnership(1, 2); } catch (OwnershipError) {}
try { $t->checkOwnership(1, 2); } catch (OwnershipError) {}
check($r->errors === 1, 'notice_denials: sent once per request');

[$t, $r] = make(mode: Telemetry::OBSERVE, logs: $logs);
check($t->checkOwnership(1, 2, 'order') === false && $r->attrs['authz.decision'] === 'allow' && $r->attrs['resource.owner_match'] === false,
    'observe: mismatch let through = the D01 signal');
$t->checkOwnership(2, 2, 'order');
check($r->attrs['resource.owner_match'] === false, 'owner_match stays false after a later match');
check(count($logs) === 1 && str_contains($logs[0], 'decision=allow owner_match=false reason=-'), 'observe: one allow+mismatch log line (L04 = D01)');

[$t, $r] = make(logs: $logs);
check($t->checkOwnership(1, 2, 'order', 'admin:read') === false && $r->attrs['authz.required_scope'] === 'admin:read'
    && $r->attrs['authz.decision'] === 'allow', 'bypass: allowed, scope sent even in MINIMAL');
check(str_ends_with($logs[0], 'bypass=admin:read'), 'bypass: log line carries the bypass');

[$t, $r] = make(Telemetry::FULL);
$t->allow();
$t->deny('scope_missing');
$t->deny('owner_mismatch');
$t->allow();
check($r->attrs['authz.decision'] === 'deny' && $r->attrs['authz.deny_reason'] === 'scope_missing', 'deny wins, first reason wins');
[$t, $r] = make(Telemetry::FULL);
$t->deny('free text');
check(!isset($r->attrs['authz.deny_reason']), 'deny_reason accepts listed values only');

[$t, $r] = make(Telemetry::FULL);
$t->checkOwnership(1, 1, 'order');
$t->checkOwnership(1, 1, 'order');
check($r->attrs['resource.check_count'] === 2 && $r->attrs['resource.type'] === 'order', 'FULL: check_count and resource.type');
$t->grantedScopes(['orders:write', 'orders:read', 'orders:read']);
check($r->attrs['authz.granted_scopes'] === 'orders:read,orders:write', 'granted scopes sorted and unique');
$t->clientType('browser');
check(!isset($r->attrs['client.type']), 'client.type accepts listed values only');

[$t, $r] = make();
$t->protocol('graphql', 'Query.order');
$t->protocol('graphql', 'Query.me');
check($r->attrs['api.protocol'] === 'graphql' && $r->attrs['api.operation'] === 'Query.me,Query.order', 'protocol and sorted operations in MINIMAL');
foreach (['Query.a', 'Query.b', 'Query.c'] as $op) { $t->protocol('graphql', $op); }
check(str_ends_with($r->attrs['api.operation'], ',…'), 'more than three operations are cut');

[$t, $r] = make();
$t->user(42);
check($r->user === Pseudonymizer::pseudonym('42', 'k') && str_starts_with($r->user, 'u_') && strlen($r->user) === 18, 'user pseudonym u_ + 16 hex');
$t2 = new Telemetry($r2 = new Recorder(), new Pseudonymizer(' '));
$t2->user(42);
check($r2->user === null, 'no key, no user ID');
check(Pseudonymizer::pseudonym('alice', 'k', 'k_', 8) === (new Pseudonymizer('k'))->apiKey('alice'), 'api key pseudonym k_ + 8 hex');

[$t, $r] = make(mode: Telemetry::OBSERVE);
$t->checkOwnership(1, 2);
$t->reset();
$t->checkOwnership(2, 2);
check($r->attrs['resource.owner_match'] === true, 'reset starts a new state (per WebSocket message / job)');

check(DecisionLog::line('deny', null, null, 'my order', str_repeat('x', 80)) ===
    'authz-radar decision=deny owner_match=- reason=- resource.type=my_order api.operation=' . str_repeat('x', 64), 'log tokens: no spaces, max 64');

[$t, $r] = make();
try { $t->checkOwnership(null, null); } catch (OwnershipError) {}
check($r->attrs['resource.owner_match'] === false, 'guest or missing owner never matches');

exit($failures === 0 ? 0 : 1);
