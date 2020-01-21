# -*- coding: utf-8 -*-

"""
Binary analysis sdk for managing and submitting hashes

Model for the configuration data.
"""
import yaml
from .errors import ConfigError


class Config:
    _required_id = 'cb-binary-analysis'
    
    def __init__(self, data):
        self._data = data
        
    @classmethod
    def load(cls, data):
        try:
            mydata = yaml.safe_load(data)
            if isinstance(mydata, dict):
                s = mydata.get('id', None)
                if s != Config._required_id:
                    raise ConfigError('Invalid configuration ID')
                s = mydata.get('version', None)
                # TODO: do some sort of version check here
                return Config(mydata)
            else:
                raise ConfigError('Invalid configuration data format')
        except yaml.YAMLError as exc:
            message = 'Load error: ' + str(exc)
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                message = message + (' at (%s,%s)' % (mark.line + 1, mark.column + 1))
            raise ConfigError(message, exc)
        
    @classmethod
    def load_file(cls, filename):
        with open(filename, 'r') as file:
            return Config.load(file)

    def _seek_path(self, path, suppress_exceptions=False):
        cur = None
        elt = None
        for s in path.split('.'):
            if cur:
                cur = cur.get(elt, None)
                if not isinstance(cur, dict):
                    if not suppress_exceptions:
                        raise ConfigError('Invalid path: ' + path)
                    return None
            else:
                cur = self._data
            elt = s
        return cur[elt]

    def string(self, path):
        v = self._seek_path(path)
        if isinstance(v, str):
            return v
        raise ConfigError('value not string type: ' + path)

    def section(self, path):
        v = self._seek_path(path)
        if isinstance(v, dict):
            return Config(v)
        raise ConfigError('value not valid section: ' + path)
