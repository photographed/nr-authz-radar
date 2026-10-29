// nr-authz-radar stage S2 for .NET (NewRelic.Agent.Api 10.x).
//
// Sends resource.owner_match and authz.decision (shared/attribute-spec.md) and a pseudonymized
// enduser.id. Call CheckOwnership right after loading a resource by a client-supplied ID.
//
// NOT COMPILED OR TESTED (no .NET SDK in the build environment). The API names
// (GetAgent, CurrentTransaction, AddCustomAttribute, SetUserId, NoticeError) were checked in the
// NewRelic.Agent.Api 10.56.0 package. NoticeError has no "expected" flag that we could find:
// configure OwnershipException as an expected error class in the agent configuration instead.
using System;
using System.Security.Cryptography;
using System.Text;

namespace AuthzRadar
{
    public sealed class OwnershipException : UnauthorizedAccessException
    {
        public OwnershipException() : base("ownership check failed") { }
    }

    /// <summary>One per request: keeps owner_match sticky and lets deny win over allow.</summary>
    public sealed class RequestState
    {
        public bool Mismatch { get; set; }
        public bool Denied { get; set; }
    }

    public static class Authz
    {
        /// <summary>"u_" + 16 hex chars, or null without a key (a plain hash can be brute-forced).</summary>
        public static string? Pseudonym(string? userId, byte[] key)
        {
            if (key.Length == 0 || userId is null) return null;
            using var hmac = new HMACSHA256(key);
            var hex = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(userId))).ToLowerInvariant();
            return "u_" + hex.Substring(0, 16);
        }

        public static void SetUser(string? userId, byte[] key)
        {
            var value = Pseudonym(userId, key);
            if (value is not null) NewRelic.Api.Agent.NewRelic.GetAgent().CurrentTransaction.SetUserId(value);
        }

        /// <param name="enforce">false (observe) lets mismatches through so detection D01 shows real IDORs.</param>
        /// <param name="bypassScope">marks legitimate cross-owner access (e.g. "admin:read") so D01 excludes it.</param>
        public static bool CheckOwnership(object ownerId, object? currentUserId, RequestState state,
                                          bool enforce = true, string? bypassScope = null)
        {
            var txn = NewRelic.Api.Agent.NewRelic.GetAgent().CurrentTransaction;
            var match = currentUserId is not null && ownerId.ToString() == currentUserId.ToString();
            if (!match) state.Mismatch = true;
            txn.AddCustomAttribute("resource.owner_match", !state.Mismatch);
            if (!match && bypassScope is not null)
            {
                txn.AddCustomAttribute("authz.required_scope", bypassScope);
            }
            else if (!match && enforce)
            {
                state.Denied = true;
                txn.AddCustomAttribute("authz.decision", "deny");
                var error = new OwnershipException();
                NewRelic.Api.Agent.NewRelic.NoticeError(error);
                throw error;
            }
            if (!state.Denied) txn.AddCustomAttribute("authz.decision", "allow");
            return match;
        }
    }
}
