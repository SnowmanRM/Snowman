import logging

logger = logging.getLogger(__name__)

def work():
	logger.debug("debug")
	logger.info("info")
	logger.warning("warning")
	logger.error("error")
	logger.critical("critical")
