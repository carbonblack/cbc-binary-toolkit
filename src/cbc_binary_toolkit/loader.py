# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""
Binary analysis sdk for managing and submitting hashes

These utility functions aid with dynamically loading objects at runtime.
"""


from importlib import import_module


def dynamic_load(full_class_name):
    """
    Loads a Python class object given its fully-qualified class name.

    Args:
        full_class_name (str): The class name of the object to be loaded.

    Returns:
        The class object.

    Raises:
        ImportError: If the class could not be loaded.

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

    Args:
        full_class_name (str): The class name of the object to be created.

    Returns:
        A new instance of that object.

    """
    class_obj = dynamic_load(full_class_name)
    return class_obj()
