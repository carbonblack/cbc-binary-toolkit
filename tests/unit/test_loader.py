

import pytest
from cb_binary_analysis.loader import dynamic_load, dynamic_create


class TestClassForLoad:
    pass


def test_dynamic_load():
    class1 = dynamic_load('test_loader.TestClassForLoad')
    assert class1
    assert class1 == TestClassForLoad
    with pytest.raises(ImportError):
        dynamic_load('bogus_package.bogus_class')


def test_dynamic_create():
    obj1 = dynamic_create('test_loader.TestClassForLoad')
    assert obj1
    assert isinstance(obj1, TestClassForLoad)
    with pytest.raises(ImportError):
        dynamic_create('bogus_package.bogus_class')
