"""Threat analysis for untrusted content.

Detectors produce a RiskReport (evidence). They never authorise anything; the
policy engine only uses a score to escalate side effects to human approval.
"""
