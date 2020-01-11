import redis
import json

r = redis.Redis(host='127.0.0.1')

"""
Tests that you can pop items off of the redis queue.
Make sure whatever key name you submit you replace the key below
"""

while True:
    data = r.blpop(['test'])
    print(json.load(data.decode()))
