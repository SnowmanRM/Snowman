#!/usr/bin/python

import util.logger
util.logger.initialize()

import logging
import examplelib.liblogging2


logger = logging.getLogger(__name__)

logger.debug("d")
logger.info("i")
logger.warning("w")
logger.error("e")
logger.critical("c")
