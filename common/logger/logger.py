import logging
import os.path

def initialize_logger(output_dir='.'):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    handler = logging.FileHandler(os.path.join(output_dir, "log"),"a")
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)-15s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
