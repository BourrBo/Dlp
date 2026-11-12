"""Validation errors must not reflect untrusted request values."""

from fastapi import Body, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from dlp_platform.public_api.errors import public_validation_error


def test_non_public_validation_error_omits_raw_input_values() -> None:
    app = FastAPI()
    app.add_exception_handler(RequestValidationError, public_validation_error)

    @app.post("/ordinary")
    def ordinary(value: str = Body()) -> dict[str, str]:
        return {"value": value}

    marker = "VALIDATION_INPUT_MUST_NOT_BE_REFLECTED"
    response = TestClient(app).post("/ordinary", json={"value": {"marker": marker}})

    assert response.status_code == 422
    assert marker not in response.text
    errors = response.json()["detail"]
    assert errors[0]["type"] == "string_type"
    assert "input" not in errors[0]
