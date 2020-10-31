def info(logger, *message):
    logger.info(_messageBuild_(message))


def debug(logger, *message):
    logger.debug(_messageBuild_(message))


def waring(logger, *message):
    logger.waring(_messageBuild_(message))


def error(logger, *message):
    logger.error(_messageBuild_(message))


def _messageBuild_(*data):
    msg = ""
    for message in data:
        msg = msg + str(data) + "|"
    return msg
