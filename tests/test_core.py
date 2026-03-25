"""
Unit tests for TeleAudit framework core components.
"""
import pytest
import asyncio
from utils.validators import validate_ip, validate_mcc_mnc, validate_authorization
from utils.imsi_tools import decode_imsi, validate_msisdn
from modules.gen4.lte_audit import LTEAudit

def test_ip_validator():
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("2001:db8::1") is True
    assert validate_ip("999.999.999.999") is False
    assert validate_ip("invalid") is False

def test_mcc_mnc_validator():
    assert validate_mcc_mnc("001", "01") is True
    assert validate_mcc_mnc("234", "15") is True
    assert validate_mcc_mnc("12", "1") is False  # MCC too short
    assert validate_mcc_mnc("001", "0001") is False # MNC too long

def test_authorization_validator():
    assert validate_authorization("AUTH-12345") is True
    assert validate_authorization("abc") is False
    assert validate_authorization("") is False

def test_imsi_decoder():
    res = decode_imsi("001010123456789")
    assert res['mcc'] == "001"
    assert res['mnc'] == "01"
    assert res['msin'] == "0123456789"

def test_msisdn_validator():
    assert validate_msisdn("+1234567890") is True
    assert validate_msisdn("1234567890") is True
    assert validate_msisdn("invalid") is False

@pytest.mark.asyncio
async def test_lte_audit_module():
    # Mock config
    config = {
        "lte": {
            "mme_ip": "127.0.0.1",
            "s1_mme_port": 36412
        }
    }
    lte_audit = LTEAudit(config)
    results = await lte_audit.run()
    
    # Verify both simulated tests ran and reported correctly
    assert len(results) == 2
    assert results[0]['test_id'] == "LTE-003"
    assert results[1]['test_id'] == "LTE-002"
    assert results[0]['severity'] == "HIGH"
