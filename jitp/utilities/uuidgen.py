import datetime
import json
import logging
import os


logging.basicConfig(
    format='%(asctime)s|%(name).10s|%(levelname).5s: %(message)s',
    level=logging.WARNING
)

log = logging.getLogger('uuidgen')
log.setLevel(logging.DEBUG)



def createEWonSerial(productCode, productNumber):
    ''' Create a EWon Product Serial Number.
    '''
    yy = str(datetime.date.today().year)[2:]
    ww = str(datetime.date.today().isocalendar()[1]).zfill(2)
    yyww = yy + ww
    productCode = str(productCode).zfill(4)
    productNumber = str(productNumber).zfill(4)

    ewonSerial = int('{}{}{}'.format(yyww, productNumber, productCode))
    log.info('Created EWon Serial Number: {}'.format(ewonSerial))
    return ewonSerial
