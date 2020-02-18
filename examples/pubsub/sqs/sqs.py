# -*- coding: utf-8 -*-

"""Default implementation of the PubSub Provider that uses SQS (LocalStack locally)."""


import boto3
import json
import time
from .manager import BaseQueue, BaseProvider, BaseProviderFactory


class SQSBasedQueue(BaseQueue):
    """
    Default implementation of the PubSub queue that uses SQS to pass along information.
    """
    def __init__(self, queue):
        self._queue = queue
        self._startpoint = time.time()
        self._msgcounter = 1

    def put(self, workitem):
        """
        Puts a new work item on the queue.

        :param workitem dict: The work item to put on the queue.
        """
        data = json.dumps(workitem)
        self._queue.send_message(MessageBody=data,
                                 MessageDeduplicationId="{}-{}".format(self._startpoint, self._msgcounter),
                                 MessageGroupId='x')
        self._msgcounter += 1

    def get(self):
        """
        Retrieves a new work item from the queue. If there are no work items available, blocks until one
        becomes available.

        :return: The first work item on the queue.
        """
        rc = None
        while rc is None:
            for msg in self._queue.receive_messages(AttributeNames=['All'], MaxNumberOfMessages=1,
                                                    WaitTimeSeconds=10):
                rc = json.loads(msg.body)
                msg.delete()
        return rc


class SQSBasedProvider(BaseProvider):
    """
    Default implementation of the PubSub provider that uses SQS to pass along information.
    """
    def __init__(self, client):
        self._client = client

    def create_queue(self, queue_name):
        """
        Creates a new PubSub queue.  If one already exists by that name, returns that instance.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        real_name = queue_name + '.fifo'
        try:
            sqsqueue = self._client.get_queue_by_name(QueueName=real_name)
        except Exception:
            sqsqueue = self._client.create_queue(QueueName=real_name, Attributes={'FifoQueue': 'true'})
        return SQSBasedQueue(sqsqueue)


class Provider(BaseProviderFactory):
    """
    Default implementation of the PubSub provider factory that uses SQS to pass along information.
    """
    def create_pubsub_provider(self, config):
        """
        Creates a new PubSub provider object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new provider factory object.
        """
        region = config.string('region')
        endpoint = config.string_default('endpoint_URL')
        keyid = config.string('access_key_id')
        key = config.string('access_key')
        session = config.string_default('session_token')
        client = boto3.resource('sqs', region_name=region, endpoint_url=endpoint, aws_access_key_id=keyid,
                                aws_secret_access_key=key, aws_session_token=session)
        return SQSBasedProvider(client)
