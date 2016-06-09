def logError(repo, error_message='', exception=None):
  err = '{0}: {1}'.format(repo, error_message)
  error_logger.error(err)
  raise ValueError(err)

def emailError():
