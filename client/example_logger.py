#!/usr/bin/python
import logging

import util.logger
from examplelib.liblogging import work

util.logger.initialize()

logger = logging.getLogger(__name__)

logger.debug("d")
logger.info("i")
logger.warning("w")
logger.error("e")
logger.critical("c")

work()
