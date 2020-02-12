



from .manager import BaseQueue, BaseProvider, BaseProviderFactory


class SQSBasedQueue(BaseQueue):
    def put(self, workitem):
        pass
        
    def get(self):
        pass


class SQSBasedProvider(BaseProvider):
    def create_queue(self, queue_name):
        pass


class Provider(BaseProviderFactory):
    def create_pubsub_provider(self, config):
        pass
    