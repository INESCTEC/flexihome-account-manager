import threading
import json
import requests
import traceback
import time
import uuid
import ssl
import hashlib
import smtplib
import pgeocode

from datetime import datetime, timedelta, timezone

from psycopg2 import OperationalError, DatabaseError

from account_manager import Config
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from account_manager import generalLogger
from account_manager.models.events import (
    UserAccountSchema,
    UserLocationSchema,
    UserRegisteredEventType,
    UserFilledPostalCodeEventType,
    UserHardDeletedEventType
)
from marshmallow import ValidationError
from account_manager.models.dbmodels import (
    db,
    DBUser,
    DBUserSettings,
    DBNotDisturb,
    DBProcessedEvent,
    DBConfirmationToken,
    DBForgotPasswordToken,
    DBAccountRecoveryToken
)

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.utils import formataddr


class EventConsumers:
    def __init__(self):
        self.exitEvent = threading.Event()

        self.threads = {}

        # Create Kafka consumer threads
        thread = threading.Thread(name='consumer',
                                  target=consumer,
                                  args=(self.exitEvent,))

        self.threads['consumer'] = thread

    # Start threads
    def start(self):
        for thread in self.threads.values():
            thread.start()

    # Stop threads and wait for them to exit
    def stop(self):
        self.exitEvent.set()

        # Join all threads
        for thread in self.threads.values():
            # logging.info('Waiting for ' + thread + ' to exit')
            thread.join()


# Function that the thread is going to execute
def consumer(exitEvent):
    generalLogger.info("Configuring Kafka consumer...")

    # Loop to keep trying to connect to broker if it is not up or an exception occurs.
    while (exitEvent.is_set() == False):
        try:
            consumer = KafkaConsumer(
                Config.KAFKA_TOPIC,
                group_id=Config.KAFKA_GROUP_ID,
                bootstrap_servers=Config.KAFKA_BROKER_ENDPOINT,
                consumer_timeout_ms=Config.KAFKA_CONSUMER_TIMEOUT_MS,
                enable_auto_commit=False,
                auto_offset_reset='earliest',
                reconnect_backoff_ms=1000,
                reconnect_backoff_max_ms=5000,
                session_timeout_ms=20000,
                max_poll_records=50
            )
            # break

        except KafkaError as e:
            generalLogger.error(e)
            generalLogger.info(
                f'Reconnecting in {Config.KAFKA_RECONNECT_SLEEP_SECONDS} seconds...'
            )

            time.sleep(Config.KAFKA_RECONNECT_SLEEP_SECONDS)
            continue

        # if exitEvent.is_set():
        #     generalLogger.info('Consumer received event. Exiting...')
        #     return

        start = time.time()
        total_time = 0
        # Consume events until the program receives an exit signal
        while not exitEvent.wait(timeout=Config.KAFKA_WAIT_FOR_EVENT_SECONDS):

            current_time = time.time()
            if current_time - start >= 300:  # Log every x seconds
                total_time += 300
                generalLogger.info(
                    f"Kafka Event Consumer thread is healthy for {total_time} seconds....")
                start = current_time

            try:
                session = db.create_scoped_session()
                msg = next(consumer)
                processEvent(session, msg)
                consumer.commit()

            except StopIteration:
                pass

            except (OperationalError, DatabaseError) as e:
                generalLogger.error(repr(e))
                traceback.print_exc()
                session.rollback()
                consumer.commit()
                continue

            except Exception as e:
                generalLogger.error(
                    "Exception occured while listening for events")
                generalLogger.error(e)
                traceback.print_exc()
                break
            
            session.close()
            # Missing sending error event to other topic

    # Close connection to the broker
    consumer.close(autocommit=False)
    generalLogger.info('Consumer received event. Exiting...')


def processEvent(session, message):
    # Print the whole event
    # print(message)

    # Convert bytes to json and retrieve the "payload" field
    event = json.loads(message.value)
    eventId = event["payload"]["eventId"]
    eventType = payload = event["payload"]["eventType"]
    payload = event["payload"]["payload"]

    # Check if event has already been processed
    processedEvent = session.query(DBProcessedEvent).filter_by(
        event_type=eventType, event_id=eventId).first()
    if (processedEvent != None):
        generalLogger.error("Event " + eventType + "/" +
                            eventId + " already processed")
        return

    generalLogger.info(f"Processing event {eventId} / {eventType}")
    try:
        if eventType == UserRegisteredEventType:
            processUserRegistedEvent(session, eventId, eventType, payload)
        elif eventType == UserFilledPostalCodeEventType:
            processPostalCodeEvent(session, eventId, eventType, payload)
        elif eventType == UserHardDeletedEventType:
            processUserHardDeletedEvent(session, eventId, eventType, payload)
    except Exception as e:
        generalLogger.error(repr(e))


def processUserRegistedEvent(session, eventId, eventType, payload):
    # Convert json to a python data structure
    userSchema = UserAccountSchema()
    try:
        payload = userSchema.loads(payload)
    except ValidationError as err:
        generalLogger.error(f"Failed to parse event payload: {err.messages}")
        return

    if payload["is_google_account"] is True:
        return

    # Create confirmation token
    m = hashlib.sha256()
    m.update(uuid.uuid4().bytes)
    m.hexdigest()

    session.query(DBConfirmationToken).filter_by(user_id=payload["user_id"]).delete()

    confirmationToken = DBConfirmationToken(user_id=payload["user_id"], token=m.hexdigest(
    ), expiration_timestamp=datetime.now(timezone.utc) + timedelta(seconds=Config.CONFIRMATION_TOKEN_EXPIRATION_TIME_SECONDS))

    session.add(confirmationToken)
    try:
        session.commit()
    except Exception as e:
        session.rollback()
        generalLogger.error(
            f"Failed to save confirmation token for user {payload['user_id']}")
        generalLogger.error(e)
        return

    generalLogger.info(
        f"Saved confirmation token for user {payload['user_id']}")

    # EMAILS DO NOT WORK ON GITLAB CI - WE DO NOT NEED THEM FOR TESTING, SO WE JUST SKIP IT
    if Config.GITLAB_CI_TEST == 'False' and Config.EMAIL is not None and Config.EMAIL_PASSWORD is not None:
        # Create a secure SSL context
        context = ssl.create_default_context()
        # Context with secure TLS protocol
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        generalLogger.info(f"SSL context: {context.protocol}")

        # Loop to secure the connection (sometimes fails when stating tls)
        max_retries = 5
        attempt = 0
        while attempt < max_retries:
            try:
                server = smtplib.SMTP("mail.inesctec.pt", 587)
                # server.ehlo()  # identify ourselves as inesctec mail client
                generalLogger.info("SMTP connection.. OK!")

                server.starttls(context=context)  # Secure the connection
                # server.ehlo()  # re-identify ourselves as an encrypted tls connection
                generalLogger.info("TLS connection.. OK!")
                break
            except Exception as e:
                attempt += 1
                generalLogger.error("Failed to login. Logging again...")
                generalLogger.error(e)
                time.sleep(2)  # Wait before attempting another tls connection

        # Failed to connect to SMTP inesctec mail client
        if attempt == max_retries:
            generalLogger.error(
                "Failed to open secure tls connection to SMTP mail client...")
            return

        sender_email = Config.EMAIL
        try:
            server.login(sender_email, Config.EMAIL_PASSWORD)
            generalLogger.info("Login.. OK!")

            # Create a multipart message and set headers
            receiver_email = payload["email"]

            message = MIMEMultipart()
            message["From"] = formataddr(
                (str(Header('Aplicação InterConnect', 'utf-8')), sender_email))
            message["To"] = receiver_email
            message["Subject"] = "Confirmação de conta de utlizador na aplicação do projeto InterConnect"

            link = "https://interconnect-dev.inesctec.pt/api/account/confirm-account/" + m.hexdigest()

            # For local test
            # link = "http://127.0.0.1:8080/api/account/confirm-account/" + m.hexdigest()

            f = open("account_manager/templates/email-confirmation.html",
                     "r", encoding="utf-8")
            body = f.read()
            f.close()
            body_aux = body.replace("LINK_LINK", link)

            f = open(
                "account_manager/static/img/INESCTECLogotipo_CORPositivo_RGB.png", "rb")
            inesc_logo = f.read()
            f.close()

            message.attach(MIMEText(body_aux, "html", "utf-8"))
            img = MIMEImage(inesc_logo)
            img.add_header(
                'Content-ID', "INESCTECLogotipo_CORPositivo_RGB.png")
            message.attach(img)

            text = message.as_string()

            server.sendmail(sender_email, receiver_email, text)

            generalLogger.info(
                "Successfully sent email with confirmation link to " + payload["email"])
        except Exception as e:
            # Print any error messages to stdout
            generalLogger.error(
                "Error in sending email with confirmation link to " + payload["email"])
            generalLogger.error(e)
        finally:
            server.quit()
            generalLogger.info("Quit... OK!")

    # Save the event has processed
    processedEvent = DBProcessedEvent(event_type=eventType, event_id=eventId)
    try:
        session.add(processedEvent)
        session.commit()
    except Exception as e:
        session.rollback()
        generalLogger.error("Failed to process event with type " +
                            eventType + " and id " + eventId)
        generalLogger.error(e)
        return

    generalLogger.info("Successfully process event with type " +
                       eventType + " and id " + eventId)


def processPostalCodeEvent(session, eventId, eventType, payload):
    generalLogger.info(f"Event Consumed: {eventType}\n")

    location_schema = UserLocationSchema()
    try:
        payload = location_schema.loads(payload)
        generalLogger.info(f"Consumed payload: {payload}\n")
    except ValidationError as err:
        generalLogger.error(f"Failed to parse event payload: {err.messages}")
        return

    if Config.GITLAB_CI_TEST == 'False':
        nomi = pgeocode.Nominatim('pt')
        location = nomi.query_postal_code(payload['postal_code']).to_dict()
        generalLogger.info(f"geo location: {location}\n")

        headers = {
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        forecast_installation_register_body = json.dumps(
            {
                "installation_code": payload['user_id'] + "_consumption",
                "country": "portugal",
                "generation": 0,
                "installation_type": "load",
                "latitude": location['latitude'],
                "longitude": location['longitude'],
                "net_power_types": "PQ",
                "source_nwp": "wrf_12km",
                "is_active": 1,
                "installed_capacity": payload['contracted_power']
            }
        )

        response = requests.post(
            f"{Config.FORECAST_INSTALLATIONS_URL}/register",
            data=forecast_installation_register_body, headers=headers
        )
        response.raise_for_status()
        response = json.loads(response.content)

        generalLogger.info(
            f"Forecast API response to register installation request:\n{response}")

        if response['code'] != 1:
            generalLogger.error(
                f"Error registering the forecast installation {response['message']}")
            raise Exception(response['message'])

    # Save the event has processed
    processedEvent = DBProcessedEvent(event_type=eventType, event_id=eventId)
    try:
        session.add(processedEvent)
        session.commit()
    except Exception as e:
        session.rollback()
        generalLogger.error("Failed to process event with type " +
                            eventType + " and id " + eventId)
        generalLogger.error(e)
        return

    generalLogger.info("Successfully process event with type " +
                       eventType + " and id " + eventId)

def processUserHardDeletedEvent(session, eventId, eventType, payload):
    generalLogger.info(f"Event Consumed: {eventType}\n")

    userSchema = UserAccountSchema()
    try:
        payload = userSchema.loads(payload)
    except ValidationError as err:
        generalLogger.error(f"Failed to parse event payload: {err.messages}")
        return

    settings = session.query(DBUserSettings).filter_by(user_id=payload['user_id']).first()
    session.query(DBNotDisturb).filter_by(settings_id=settings.id).delete()
    session.query(DBUserSettings).filter_by(user_id=payload['user_id']).delete()
    session.query(DBUser).filter_by(user_id=payload['user_id']).delete()
    session.query(DBConfirmationToken).filter_by(user_id=payload['user_id']).delete()
    session.query(DBForgotPasswordToken).filter_by(user_id=payload['user_id']).delete()
    session.query(DBAccountRecoveryToken).filter_by(user_id=payload['user_id']).delete()

    # Save the event has processed
    processedEvent = DBProcessedEvent(event_type=eventType, event_id=eventId)
    try:
        session.add(processedEvent)
        session.commit()
    except Exception as e:
        session.rollback()
        generalLogger.error("Failed to process event with type " +
                            eventType + " and id " + eventId)
        generalLogger.error(e)
        return

    generalLogger.info("Successfully process event with type " +
                       eventType + " and id " + eventId)
