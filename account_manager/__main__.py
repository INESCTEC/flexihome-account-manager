#!/usr/bin/env python3

from waitress import serve
from account_manager import connexionApp, app
from account_manager.eventConsumers import EventConsumers
from account_manager.save_meter_id_api_key_mapping import saveMeterIdApiKeyMapping


def main():
    # Register our API in connexion
    connexionApp.add_api('openapi.yaml',
                         arguments={'title': 'Account Manager Service'},
                         pythonic_params=True,
                         validate_responses=True)

    # Iniciar aqui a thread do SSA

    saveMeterIdApiKeyMapping("account_manager/meter_id_api_key_mapping.csv")

    # Create the EventConsumers object
    ec = EventConsumers()
    # Start event threads
    ec.start()

    # Start web server to serve our REST API (the program waits until an exit signal is received)
    serve(app, host='0.0.0.0', port=8080)

    # After the web server exists, stop the event threads
    ec.stop()


if __name__ == '__main__':
    main()
