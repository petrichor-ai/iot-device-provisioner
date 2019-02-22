import datetime



def createEWonSerial(productCode, productNumber):
    ''' Create a EWon Product Serial Number.
    '''
    yy = str(datetime.date.today().year)[2:]
    ww = str(datetime.date.today().isocalendar()[1]).zfill(2)
    yyww = yy + ww
    productCode = str(productCode).zfill(4)
    productNumber = str(productNumber).zfill(6)
    return int('{}{}{}'.format(yyww, productNumber, productCode))
