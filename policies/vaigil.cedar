// Vaigil rules in Cedar. Not wired in yet: v0.2 replaces the Go rules
// in internal/policy with the cedar-go engine reading this file.
// In Cedar, a forbid always beats a permit.

// Read-only tools are always allowed.
permit (principal, action == Action::"read_inbox", resource);

// Egress tools are allowed by default...
permit (principal, action in [Action::"send_email", Action::"web_fetch"], resource);

// ...but never with data copied from an untrusted tool result, unless the
// user named the recipient themselves (fixes the allowlist-abuse bypass).
forbid (principal, action in [Action::"send_email", Action::"web_fetch"], resource)
when { context.args_carry_tainted_data && !context.recipient_named_by_user };

// No email to an address the user never named once the context is tainted.
forbid (principal, action == Action::"send_email", resource)
when { context.session_tainted && !context.recipient_named_by_user };

// No fetch outside the allowlist once the context is tainted.
forbid (principal, action == Action::"web_fetch", resource)
when { context.session_tainted && !context.domain_allowlisted };
