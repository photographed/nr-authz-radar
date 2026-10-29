# authz-radar-spring

Spring Boot / Spring Security instrumentation for [nr-authz-radar](../../README.md).
Sends the authorization attributes from [`shared/attribute-spec.md`](../../shared/attribute-spec.md) to New Relic.

- Default: stage S2 (`authz.decision`, `resource.owner_match`, HMAC-pseudonymized `enduser.id`)
- `@CheckOwnership` on the data-access method, `Owned` on the entity
- OBSERVE mode first (record only), then ENFORCE (deny)

```bash
./gradlew build                                  # Spring Boot 3.5.16 (tested)
./gradlew test -PspringBootVersion=4.1.2         # Spring Boot 4.1 (tested)
```

Not published to Maven Central yet. Usage (Japanese): [`instrumentation-java.md`](../../skills/nr-appsec-guard/references/instrumentation-java.md)
