<?php
declare(strict_types=1);

require __DIR__ . '/AuthzRadar.php';

use AuthzRadar\AuthzRadar;
use AuthzRadar\OwnershipError;
use AuthzRadar\RequestState;

$failures = 0;
function check(bool $ok, string $name): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . PHP_EOL;
    $failures += $ok ? 0 : 1;
}

function fake(): array
{
    $rec = new ArrayObject(['attrs' => [], 'errors' => 0, 'user' => null]);
    $api = [
        'attr' => static function (string $k, $v) use ($rec) { $a = $rec['attrs']; $a[$k] = $v; $rec['attrs'] = $a; },
        'user' => static function (string $v) use ($rec) { $rec['user'] = $v; },
        'error' => static function (Throwable $e) use ($rec) { $rec['errors']++; },
    ];
    return [new AuthzRadar($api), $rec];
}

[$ar, $rec] = fake();
check($ar->checkOwnership('alice', 'alice', new RequestState()) === true
    && $rec['attrs'] === ['resource.owner_match' => true, 'authz.decision' => 'allow'], 'owner is allowed');

[$ar, $rec] = fake();
try {
    $ar->checkOwnership('bob', 'alice', new RequestState());
    check(false, 'mismatch is denied');
} catch (OwnershipError $e) {
    check($rec['attrs'] === ['resource.owner_match' => false, 'authz.decision' => 'deny'] && $rec['errors'] === 1, 'mismatch is denied');
}

[$ar, $rec] = fake();
$s = new RequestState();
$ar->checkOwnership('bob', 'alice', $s, false);
$ar->checkOwnership('alice', 'alice', $s, false);
check($rec['attrs'] === ['resource.owner_match' => false, 'authz.decision' => 'allow'], 'observe mode is sticky');

[$ar, $rec] = fake();
$ar->checkOwnership('bob', 'ops', new RequestState(), true, 'admin:read');
check(($rec['attrs']['authz.required_scope'] ?? null) === 'admin:read', 'bypass is labelled');

[$ar, $rec] = fake();
$ar->setUser('alice', 'k');
check((bool) preg_match('/^u_[0-9a-f]{16}$/', (string) $rec['user']) && AuthzRadar::pseudonym('alice', '') === null, 'user is pseudonymized');

(new AuthzRadar())->checkOwnership('alice', 'alice', new RequestState()); // no agent installed: must not fail
check(true, 'works without the agent extension');

exit($failures === 0 ? 0 : 1);
