import logging
from logging import handlers

def init_logger(log_file, email_errors=False, log_level="INFO"):
    #logger
    logger = logging.getLogger('certman')
    logger.setLevel(getattr(logging, log_level))

    #formatters
    ch_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    eh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    #console logger
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)

    if email_errors['enabled'] and email_errors['email']:
        #email logger
        eh = logging.handlers.SMTPHandler(mailhost=(email_errors['smtp_host'], email_errors['smtp_port']),
                                            fromaddr=email_errors['from_address'],
                                            toaddrs=email_errors['email'],
                                            subject="Certman Error")
        eh.setLevel(logging.WARNING)
        logger.addHandler(eh)

    return logger
