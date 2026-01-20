from account_manager import logger, app
from account_manager.models.dbmodels import DBUser


@app.route('/health')
def healthy():
    corId = {'X-Correlation-ID': 'health'}

    user = DBUser.query.first()

    logger.debug("Heath endpoint OK", extra=corId)

    return ''
