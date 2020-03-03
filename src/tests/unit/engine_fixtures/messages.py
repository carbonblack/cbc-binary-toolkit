"""Engine fixtures for testing"""

IOCS_1 = [{
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


UNFINISHED_STATE = {
    "file_size": 2000000,
    "file_name": "blort.exe",
    "os_type": "WINDOWS",
    "engine_name": "!!REPLACE!!",
    "time_sent": "2020-01-15T12:00:00",
    "time_returned": "2020-01-15T12:05:00"
}

FINISHED_STATE = {
    "file_size": 2000000,
    "file_name": "foobar.exe",
    "os_type": "WINDOWS",
    "engine_name": "!!REPLACE!!",
    "time_sent": "2020-01-14T12:00:00",
    "time_returned": "2020-01-14T12:05:00",
    "time_published": "2020-01-14T12:05:01"
}

MESSAGE_VALID = {
    "iocs": IOCS_1,
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"
}
