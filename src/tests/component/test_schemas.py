# -*- coding: utf-8 -*-

"""Test code for the schemas"""


import pytest

from schema import SchemaError
from cbc_binary_toolkit.schemas import (
    BinaryMetadataSchema,
    EngineResponseSchema,
    IOCv2SEVSchema,
    ReportSchema
)
from tests.component.schema_fixtures.mock_data import (
    # BinaryMetadataSchema
    VALID_BINARY_METADATA,
    INVALID_SHA256_BINARY_METADATA,
    INVALID_MD5_BINARY_METADATA,
    EMPTY_URL_BINARY_METADATA,
    MISSING_FIELDS_BINARY_METADATA,

    # EngineResponseSchema
    VALID_ENGINE_RESPONSE,
    INVALID_SHA256_ENGINE_RESPONSE,

    # IOCv2SEVSchema
    VALID_IOCV2,
    INVALID_SEVERITY_IOCV2,
    INVALID_MATCH_TYPE_IOCV2,
    MISSING_VALUE_IOCV2,

    # ReportSchema
    VALID_REPORT,
    INVALID_SEVERITY_REPORT,
    MISSING_PROPERTIES_REPORT
)

# ==================================== Unit TESTS BELOW ====================================


@pytest.mark.parametrize("input", [
    VALID_BINARY_METADATA
])
def test_BinaryMetadataSchema(input):
    """Test schema success"""
    assert BinaryMetadataSchema.validate(input)


@pytest.mark.parametrize("input", [
    INVALID_SHA256_BINARY_METADATA,
    INVALID_MD5_BINARY_METADATA,
    EMPTY_URL_BINARY_METADATA,
    MISSING_FIELDS_BINARY_METADATA
])
def test_BinaryMetadataSchema_failure(input):
    """Test schema failure"""
    with pytest.raises(SchemaError):
        BinaryMetadataSchema.validate(input)


@pytest.mark.parametrize("input", [
    VALID_ENGINE_RESPONSE
])
def test_EngineResponseSchema(input):
    """Test schema success"""
    assert EngineResponseSchema.validate(input)


@pytest.mark.parametrize("input", [
    INVALID_SHA256_ENGINE_RESPONSE
])
def test_EngineResponseSchema_failure(input):
    """Test schema failure"""
    with pytest.raises(SchemaError):
        EngineResponseSchema.validate(input)


@pytest.mark.parametrize("input", [
    VALID_IOCV2
])
def test_IOCv2SEVSchema(input):
    """Test schema success"""
    assert IOCv2SEVSchema.validate(input)


@pytest.mark.parametrize("input", [
    INVALID_SEVERITY_IOCV2,
    INVALID_MATCH_TYPE_IOCV2,
    MISSING_VALUE_IOCV2
])
def test_IOCv2SEVSchema_failure(input):
    """Test schema failure"""
    with pytest.raises(SchemaError):
        IOCv2SEVSchema.validate(input)


@pytest.mark.parametrize("input", [
    VALID_REPORT
])
def test_ReportSchema(input):
    """Test schema success"""
    assert ReportSchema.validate(input)


@pytest.mark.parametrize("input", [
    INVALID_SEVERITY_REPORT,
    MISSING_PROPERTIES_REPORT
])
def test_ReportSchema_failure(input):
    """Test schema failure"""
    with pytest.raises(SchemaError):
        ReportSchema.validate(input)
