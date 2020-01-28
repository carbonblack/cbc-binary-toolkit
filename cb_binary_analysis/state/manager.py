

from cb_binary_analysis.loader import dynamic_create


class StateManager:
    def __init__(self, config):
        factory_classname = config.string('database._provider')
        factory = dynamic_create(factory_classname)
        self._persistor = factory.create_persistor(config.section('database'))
        
        