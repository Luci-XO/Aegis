"""Security core: schemas, policy engine, gateway, approvals and audit log.

Nothing in this package imports an LLM client. The gateway must keep enforcing
policy when no model or detector is available.
"""
