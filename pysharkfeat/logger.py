"""
GPL V3 license

Copyright (C) 2022 Zhi Liu<cowliucd@gmail.com>

logger.py
This file is part of Pysharkfeat, a feature extraction tool from encrypted traffic. See LICENSE for more information.

"""

import logging

logger = logging.getLogger()

formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")

console_handler = logging.StreamHandler()
file_handler = logging.FileHandler("pysharkfeat.log")

console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# you can set other levels(such ash logging.INFO) to disable processing details
logger.setLevel(logging.DEBUG)

