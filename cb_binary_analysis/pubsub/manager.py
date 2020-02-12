# -*- coding: utf-8 -*-

"""The high-level management for the PubSub queue system."""


from cb_binary_analysis.loader import dynamic_create


class BaseQueue:
    def put(self, workitem):
        raise NotImplementedError("protocol not implemented: put")
        
    def get(self):
        raise NotImplementedError("protocol not implemented: get")
        
        
class BaseProvider:
    def create_queue(self, queue_name):
        raise NotImplementedError("protocol not implemented: create_queue")
        
        
class BaseProviderFactory:
    def create_pubsub_provider(self, config):
        raise NotImplementedError("protocol not implemented: create_pubsub_provider")
        
        
class PubSubManager:
    def __init__(self, config):
        factory_classname = config.string('pubsub._provider')
        factory = dynamic_create(factory_classname)
        self._provider = factory.create_pubsub_provider(config.section('pubsub'))

    def create_queue(self, queue_name):
        return self._provider.create_queue(queue_name)
    