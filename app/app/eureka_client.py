import sys
from py_eureka_client import eureka_client
import os
import socket
from dotenv import load_dotenv

load_dotenv()


async def init_eureka(conf):
    try:
        print("Initializing Eureka client...")
        eureka_url = conf.get('server')
        app_name = conf.get('app_name')
        app_port = conf.get('port')
        
        try:
            # This gets the local IP address that would be used to connect to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = os.getenv('APP_HOST', '0.0.0.0')
        
        app_host = local_ip
        if not eureka_url or not app_name:
            print(f"Configuration Eureka incomplète: eureka_url={eureka_url}, app_name={app_name}")
            return
            
        print(f"Enregistrement auprès d'Eureka: {app_name} vers {eureka_url}")

        await eureka_client.init_async(
            eureka_server=eureka_url,
            app_name=app_name,
            instance_port=app_port,
            instance_host=app_host,
            renewal_interval_in_secs=30,
            duration_in_secs=90,
            metadata={
                "zone": "primary",
                "securePortEnabled": "false",
                "securePort": "443",
                "statusPageUrl": f"http://{app_host}:{app_port}/api/user-service/info",
                "healthCheckUrl": f"http://{app_host}:{app_port}/api/user-service/health"
            }
        )
        print(f"Enregistrement auprès d'Eureka réussi")
    except Exception as e:
        print(f"Error initializing Eureka client: {e}")
        sys.exit(1)



import signal
import asyncio

def deregister_and_exit(signum, frame):
    """Synchronous signal handler that properly handles async cleanup"""
    print('Stopping eureka client...')
    try:
        # Try to get the current event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is running, schedule the cleanup as a task
            loop.create_task(cleanup_eureka())
        else:
            # If no loop is running, create one and run the cleanup
            loop.run_until_complete(cleanup_eureka())
    except RuntimeError:
        # No event loop available, create a new one
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(cleanup_eureka())
            loop.close()
        except Exception as e:
            print(f"Error during Eureka cleanup: {e}")
    finally:
        sys.exit(0)

async def cleanup_eureka():
    """Async function to properly cleanup Eureka client"""
    try:
        await eureka_client.stop_async()
        print('Eureka client stopped successfully')
    except Exception as e:
        print(f"Error stopping Eureka client: {e}")

signal.signal(signal.SIGINT, deregister_and_exit)
signal.signal(signal.SIGTERM, deregister_and_exit)
