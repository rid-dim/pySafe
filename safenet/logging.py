########################################################################################################################
#
# Logging utils
#
# For now, just putting in a backbone for nice printing, plus the ability to write detailed debug log files.
# Not hooked into anything just yet, we need to debate how/when to use it instead of print
# Very useful during dev to have a very detailed log
#
#
########################################################################################################################

import logging
import safenet.localization
import os

# If the log directory does not exist, create it
if not os.path.exists(safenet.localization.LOGPATH):
    os.mkdir(safenet.localization.LOGPATH)

#
logfile = os.path.join(safenet.localization.LOGPATH, 'log.txt')

############
# Formatters and other definitions
############

logger = None
logstream = None
logname = 'safenet'

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
CRITICAL = logging.CRITICAL
FATAL = logging.FATAL

simpleformatter = logging.Formatter('[%(asctime)s] %(name)s:%(levelname)s -> %(message)s', datefmt='%I:%M:%S %p')
deluxeformatter = logging.Formatter("[%(asctime)s] %(name)-8s [%(levelname)8s] %(message)-74s ", "%H:%M:%S")
debugformatter = logging.Formatter("[%(asctime)s] %(name)-8s [%(levelname)8s] %(message)-64s (%(filename)s:%(lineno)s)",
                                   "%H:%M:%S")
systemonlyformatter = logging.Formatter("[%(asctime)s] %(name)-8s %(message)-72s (%(filename)s:%(lineno)s)", "%H:%M:%S")
formats = {'simple': simpleformatter,
           'deluxe': deluxeformatter,
           'debug': debugformatter,
           'systemonly': systemonlyformatter}


############
# LOGGING FUNCTIONS
############

def setup_logger(style='debug', log_to_file=True, start_msg_threshold=logging.DEBUG, stream=None):
    global logger, logstream
    logger = logging.getLogger(logname)
    formatter_choice = formats.get(style, None)
    if formatter_choice is None:
        print(f'format style {style} not available. Defaulting to debug')
        formatter_choice = debugformatter

    logstream = logging.StreamHandler(stream=stream)
    logstream.setLevel(start_msg_threshold)
    logstream.setFormatter(formatter_choice)
    logger.addHandler(logstream)

    #  This controls the first filter .. any message above this threshold can be further filtered at the
    #  stream and file levels seperately
    logger.setLevel(start_msg_threshold)

    if log_to_file:
        try:
            system_logfile = logging.FileHandler(logfile, mode='w')
            system_logfile.setLevel(start_msg_threshold)
            system_logfile.setFormatter(debugformatter)
            logger.addHandler(system_logfile)
        except:
            logger.system('Logfile: {0} bad, no logfile output'.format(logfile))

    # logger.debug(f'Logger initialized for "{logname}", with starting level {start_msg_threshold}')
    return logger


if __name__ == '__main__':
    setup_logger()
    logger.critical('Testing: 1,2,3')
