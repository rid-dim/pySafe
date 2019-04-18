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

# Set widest possible console on windows systems
os.system("mode con lines=60 cols=128")

# If the log directory does not exist, create it
if not os.path.exists(safenet.localization.LOGPATH):
    os.mkdir(safenet.localization.LOGPATH)

logfile = os.path.join(safenet.localization.LOGPATH, 'log.txt')

###################################
# Formatters and other definitions
###################################

DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

# Formatting Styles
printformatter = logging.Formatter('%(levelname)s: %(message)s')
simpleformatter = logging.Formatter('[%(asctime)s] %(name)s:%(levelname)s -> %(message)s', datefmt='%I:%M:%S %p')
deluxeformatter = logging.Formatter("[%(asctime)s] %(name)-8s [%(levelname)8s] %(message)-74s ", "%H:%M:%S")
debugformatter = logging.Formatter("[%(asctime)s%(msecs)03d] %(name)-11s:%(threadName)-10s(%(filename)18s:%(lineno)4s) [%(levelname)8s] %(message)-64s",
                                   "%H:%M:%S.")

formats = {'simple': simpleformatter,
           'deluxe': deluxeformatter,
           'debug': debugformatter,
           'print': printformatter}

levels = {'debug'   : DEBUG,
          'info'    : INFO,
          'warning' : WARNING,
          'error'   : ERROR,
          'critical': CRITICAL}

############
# LOGGING FUNCTIONS
############
def _set_level(obj,lvl):
    if isinstance(lvl,str):
        lvl=levels.get(lvl,DEBUG)
    obj.setLevel(lvl)

def _set_style(obj,sty):
    if not isinstance(sty,logging.Formatter):
        sty=formats.get(sty,debugformatter)
    obj.setFormatter(sty)

def print_only_setup():
    '''
    a default setup that makes all logs look like normal print statements
    '''
    log=logging.getLogger(cfg.GLOBAL_LOGGER_NAME)
    logstream = logging.StreamHandler(stream=sys.stdout)
    log.setLevel(levels.get(cfg.GLOBAL_MASTER_HIGHPASS))
    logstream.setFormatter(printformatter)
    log.addHandler(logstream)

print_only_setup()

def setup_logger(**kwargs):
    logger = logging.getLogger(cfg.GLOBAL_LOGGER_NAME)

    internal_handlers=[]  # double stdout bugfix

    # Read styles and detail levels from config.py, with any passed in kwargs overriding
    stream=kwargs.get('stream',sys.stdout)
    file_style = kwargs.get('file_style', formats.get(cfg.GLOBAL_FILE_LOG_FORMAT,debugformatter))
    std_style = kwargs.get('std_style', formats.get(cfg.GLOBAL_STD_LOG_FORMAT,debugformatter))

    file_level = kwargs.get('file_level',levels.get(cfg.GLOBAL_FILE_LOG_HIGHPASS, DEBUG))
    std_level = kwargs.get('file_level',levels.get(cfg.GLOBAL_STD_LOG_HIGHPASS, DEBUG))
    master_level = kwargs.get('master_level',levels.get(cfg.GLOBAL_MASTER_HIGHPASS, DEBUG))

    enable_file=kwargs.get('enable_file',cfg.GLOBAL_ENABLE_FILE_LOGGING)
    enable_stream=kwargs.get('enable_stream',cfg.GLOBAL_ENABLE_FILE_LOGGING)

    #  This controls the first filter .. any message above this threshold can be further filtered at the
    #  stream and file levels seperately
    _set_level(logger,master_level)

    if enable_stream:
        logstream = logging.StreamHandler(stream=stream)
        _set_level(logstream,std_level)
        _set_style(logstream,std_style)
        logger.addHandler(logstream)
        internal_handlers.append(logstream)

    if enable_file:
        try:
            system_logfile = logging.FileHandler(logfile, mode='w')
            _set_level(system_logfile, file_level)
            _set_style(system_logfile, file_style)
            internal_handlers.append(system_logfile)
            logger.addHandler(system_logfile)
        except:
            logger.fatal('Logfile: {0} bad, no logfile output'.format(logfile))

    logger.handlers=internal_handlers
    global logger_set_up
    logger_set_up=True
    logger.debug(f'logger initialized. File: {enable_file}, Stream: {enable_stream}')

if cfg.GLOBAL_AUTO_INIT_LOGGING:
    setup_logger()

log = logging.getLogger(cfg.GLOBAL_LOGGER_NAME)

if __name__ == '__main__':
    pass
