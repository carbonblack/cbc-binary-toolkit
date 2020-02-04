# -*- coding: utf-8 -*-

"""
Binary analysis sdk for managing and submitting hashes

These utility functions aid with dynamically loading objects at runtime.
"""


from importlib import import_module


def dynamic_load(full_class_name):
    """
    Loads a Python class object given its fully-qualified class name.

    :param full_class_name str: The class name of the object to be loaded.
    :return: The class object.
    """
    try:
        module_path, class_name = full_class_name.rsplit('.', 1)
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        raise ImportError(full_class_name) from e


def dynamic_create(full_class_name):
    """
    Creates a Python object given its fully-qualified class name.

    :param full_class_name str: The class name of the object to be created.
    :return: A new instance of that object.
    """
    class_obj = dynamic_load(full_class_name)
    return class_obj()
