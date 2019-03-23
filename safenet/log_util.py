########################################################################################################################
#
# Logging utils
#
# For now, just putting in a backbone for nice printing, plus the ability to write detailed debug log files.
# Not hooked into anything just yet, we need to debate how/when to use it instead of print
#
# To use, edit config.py for settings and import logger from this file
#
########################################################################################################################

import logging
import safenet.localization
import safenet.config as cfg
import os
import sys

# If the log directory does not exist, create it
if not os.path.exists(safenet.localization.LOGPATH):
    os.mkdir(safenet.localization.LOGPATH)

logfile = os.path.join(safenet.localization.LOGPATH, 'log.txt')

############
# Formatters and other definitions
############

class MockLogger():
    '''
    Intercepts any logging call and prints the message.  Default, possible to convert all print statements to logs with
    no change in syntax between levels of logging from print to super detailed.
    '''
    def __getattr__(self, item):
        return self
    def __call__(self, *args, **kwargs):
        if len(args)>0:
            print(args[0])
        else:
            print('Mock logger called with no message')

logger=MockLogger()
logger_set_up = False

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

# Formatting Styles
simpleformatter = logging.Formatter('[%(asctime)s] %(name)s:%(levelname)s -> %(message)s', datefmt='%I:%M:%S %p')
deluxeformatter = logging.Formatter("[%(asctime)s] %(name)-8s [%(levelname)8s] %(message)-74s ", "%H:%M:%S")
debugformatter = logging.Formatter("[%(asctime)s%(msecs)03d] %(name)-8s [%(levelname)8s] %(message)-64s (%(filename)s:%(lineno)s)",
                                   "%H:%M:%S.")

formats = {'simple': simpleformatter,
           'deluxe': deluxeformatter,
           'debug': debugformatter}

levels = {'debug'   : DEBUG,
          'info'    : INFO,
          'warning' : WARNING,
          'error'   : ERROR,
          'critical': CRITICAL}

############
# LOGGING FUNCTIONS
############

def setup_logger(log_to_file=True, log_to_stdout=False, stream=sys.stdout):
    global logger
    logger = logging.getLogger(cfg.GLOBAL_LOGGER_NAME)

    internal_handlers=[]  # double stdout bugfix

    # Read styles and detail levels from config.py
    file_style = formats.get(cfg.GLOBAL_FILE_LOG_FORMAT,debugformatter)
    std_style = formats.get(cfg.GLOBAL_STD_LOG_FORMAT,debugformatter)

    file_level = levels.get(cfg.GLOBAL_FILE_LOG_HIGHPASS, DEBUG)
    std_level = levels.get(cfg.GLOBAL_STD_LOG_HIGHPASS, DEBUG)
    master_level = levels.get(cfg.GLOBAL_MASTER_HIGHPASS, DEBUG)

    #  This controls the first filter .. any message above this threshold can be further filtered at the
    #  stream and file levels seperately
    logger.setLevel(master_level)

    if cfg.GLOBAL_ENABLE_STD_LOGGING:
        logstream = logging.StreamHandler(stream=stream)
        logstream.setLevel(std_level)
        logstream.setFormatter(std_style)
        logger.addHandler(logstream)
        internal_handlers.append(logstream)

    if cfg.GLOBAL_ENABLE_FILE_LOGGING:
        try:
            system_logfile = logging.FileHandler(logfile, mode='w')
            system_logfile.setLevel(file_level)
            system_logfile.setFormatter(file_style)
            internal_handlers.append(system_logfile)
            logger.addHandler(system_logfile)
        except:
            logger.fatal('Logfile: {0} bad, no logfile output'.format(logfile))

    logger.handlers=internal_handlers
    global logger_set_up
    logger_set_up=True

if not logger_set_up and cfg.GLOBAL_AUTO_INIT_LOGGING:
    setup_logger()

if __name__ == '__main__':
    logger.error('Testing: 1,2,3')
