"""Engine fixtures for testing"""

iocs = [{
        "id": "j39sbv7",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
        },
        {
        "id": "j39sbv7",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
        },
        {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["app.exe"],
        "severity": 10,
        },
        {
        "id": "0kdl4uf9",
        "match_type": "regex",
        "values": [".*google.*"],
        "severity": 3,
        }]

MESSAGE_VALID = {
    "iocs": iocs,
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"
}
