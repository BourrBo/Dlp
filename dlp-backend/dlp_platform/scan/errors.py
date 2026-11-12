"""Stable, safe scan pipeline errors."""


class ScanPipelineError(Exception):
    code = "scan_failed"
    status_code = 500
    public_message = "Scan could not be completed"


class IdempotencyConflict(ScanPipelineError):
    code = "idempotency_conflict"
    status_code = 409
    public_message = "Request ID was already used with different input"


class IdempotencyInProgress(ScanPipelineError):
    code = "idempotency_in_progress"
    status_code = 409
    public_message = "A scan with this request ID is already in progress"


class ScanInputTooLarge(ScanPipelineError):
    code = "request_too_large"
    status_code = 413
    public_message = "Scan input exceeds the configured size limit"


class DetectorFailure(ScanPipelineError):
    code = "detector_failed"
    status_code = 502
    public_message = "Detection could not be completed"


class PolicyDecisionFailure(ScanPipelineError):
    code = "policy_decision_failed"
    status_code = 502
    public_message = "Policy decision could not be completed"


class ScanStorageFailure(ScanPipelineError):
    code = "scan_storage_failed"
    status_code = 503
    public_message = "Scan could not be recorded"


class PipelineUnavailable(ScanPipelineError):
    code = "scan_pipeline_unconfigured"
    status_code = 503
    public_message = "Scan pipeline is not configured"
