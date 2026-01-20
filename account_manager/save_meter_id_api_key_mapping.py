import csv

from account_manager import generalLogger, db
from account_manager.models.dbmodels import DBMeterIdApiKeyMapping

from sqlalchemy.dialects.postgresql import insert


def saveMeterIdApiKeyMapping(file):
    generalLogger.info(f"Opening {file} file...")
    f = open(file, "r")

    mapping = csv.reader(filter(lambda row: row[0] != "#", f), delimiter=',')
    next(mapping, None)
    for row in mapping:
        if row[1] == "":
            row[1] = None
        stmt = insert(DBMeterIdApiKeyMapping).values(meter_id=row[0], api_key=row[1])
        do_update_stmt = stmt.on_conflict_do_update(
            index_elements=['meter_id'],
            set_=dict(api_key=row[1])
        )
        db.session.execute(do_update_stmt)
  
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        generalLogger.error(
            f"Failed to save new Meter IDs and API Keys mapping to the database")
        generalLogger.error(e)
        return

    generalLogger.info(
        f"Successfully saved new Meter IDs and API Keys mapping to the database")
