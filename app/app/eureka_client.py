import sys
import py_eureka_client.eureka_client as eureka_client
import os


def init_eureka(conf):
    # Get the container name from the environment variable or use a fallback method
    container_name = os.environ.get('HOSTNAME', 'user-service')
    # Use the container name or a unique identifier for the instance ID
    #instance_id = f"{conf.get('app_name')}-{container_name}"
    
    eureka_client.init(eureka_server=conf.get('server'),
                       app_name=conf.get('app_name'),
                       instance_ip="user-service",  # Or use the Docker service name
                       instance_host="user-service",
                       instance_port=conf.get('port'))



import signal

def deregister_and_exit(signal, frame):
    print('stop eureka client')
    eureka_client.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, deregister_and_exit)
signal.signal(signal.SIGTERM, deregister_and_exit)
