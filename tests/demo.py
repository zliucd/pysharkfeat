"""
GPL V3 license

Copyright (C) 2022 Zhi Liu<zliucd66@gmail.com>

demo.py
This file is part of Pysharkfeat, a feature extraction tool from encrypted traffic. See LICENSE for more information.

"""

from pysharkfeat.featextractor import FeatureExtractor

# specify pcap file or pcap dir and output dir
pcap_dir = "./pcaps/tiny_pcaps"
output_dir="./output"

extractor = FeatureExtractor(pcap_path=pcap_dir, output_dir=output_dir)
summary = extractor.main_extract_pcaps_feat()

print(summary)