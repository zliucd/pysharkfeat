"""
GPL V3 license

Copyright (C) 2022 Zhi Liu<cowliucd@gmail.com>

featextractor.py
This file is part of Pysharkfeat, a feature extraction tool from encrypted traffic. See LICENSE for more information.

"""

from pysharkfeat.stream import Pkt, Stream
from pysharkfeat.util import run_tshark_command, test_tshark, format_tshark_results
from pysharkfeat.logger import logger

import os, json
from pathlib import Path
from datetime import datetime

class FeatureExtractor:
    """
    Main class of PysharkFeat
    """
    def __init__(self, pcap_path, output_dir="./output"):
        """
        Initiator of FeatureExtractor
        :param pcap_path(str): pcap path, which could be a file or a dir
        :param output_dir(str): dir where feature files in JSON to be saved,
                                default location is ./output; if set to none, don't save features.

        """

        self.pcap_path = os.path.abspath(pcap_path)
        self.output_dir = output_dir

        # test if tshark works properly
        test_tshark()

    def main_extract_pcaps_feat(self):
        """
        Main function to be called to generate features
        :return: output_summary(string): analysis summary
        """

        pcap_files = []

        # start clocking
        start_time = datetime.now()

        if os.path.isfile(self.pcap_path):
            pcap_files.append(self.pcap_path)
        elif os.path.isdir(self.pcap_path):
            for root, dir_names, file_names in os.walk(self.pcap_path):
                for f in file_names:
                    if f[0:2] != "._" and f[-5:] == ".pcap":
                        pcap_files.append(os.path.join(root, f))

        else:
            err_msg = "Pcap path invalid. Please check the pcap path :%s" % self.pcap_path
            logger.error(err_msg)
            raise Exception(err_msg)

        tls_num = 0

        for pcap_path in pcap_files:
            pcap_name = Path(pcap_path).name
            logger.info("Begin to analyze %s" % pcap_name)
            pcap_feats_dict = dict()

            pcap_feats = self.extract_pcap_feat(pcap_path)

            tls_num += len(pcap_feats)

            pcap_feats_dict[pcap_name] = pcap_feats

            self.save_feats(pcap_feats)

        end_time = datetime.now()
        elapsed_seconds = (end_time - start_time).total_seconds()

        output = dict()
        output["summary"] = dict()
        output["summary"]["software"] = "Pysharkfeat"
        output["summary"]["start_time"] = start_time.strftime("%Y-%m-%d, %H:%M:%s")
        output["summary"]["end_time"] = start_time.strftime("%Y-%m-%d, %H:%M:%s")
        output["summary"]["elapsed"] = str(elapsed_seconds) + " seconds"
        output["summary"]["pcap_files"] = len(pcap_files)
        output["summary"]["TLS_stream_num"] = tls_num

        output["feats"] = pcap_feats_dict;

        summary_output = json.dumps(output["summary"], indent=4)

        logger.info("Feature extraction finished, feature files have been saved to %s" % self.output_dir)
        logger.info(summary_output)

        return summary_output


    def extract_pcap_feat(self, pcap_path):
        """
        Main function to analyze and extract features from a single pcap
        :param pcap_path(str): pcap path
        :return: feats(list): features for the pcap
        """

        stream_dict = self.preprocess_pcap(pcap_path)
        feats = self.generate_streams_feat(stream_dict)

        return feats


    def preprocess_pcap(self, pcap_file_path):
        """
        Preprocess pcap with tshark
        :param pcap_file_path(str): pcap path
        :return: stream_dict(dict): streams in the pcap
        """

        stream_dict = dict()

        tshark_cmd = ("tshark -r %s -Y 'ssl' -T fields -e tcp.stream" % pcap_file_path)
        result = run_tshark_command(tshark_cmd)

        if result == None:
            return stream_dict

        stream_indexes = []
        for line in result:
            tmp = line.replace("\n","")
            tmp_idx = int(tmp)
            if tmp_idx not in stream_indexes:
                stream_indexes.append(tmp_idx)

        for stream_index in stream_indexes:
            tshark_cmd = "tshark -r %s -Y 'ssl' -Y 'tcp.stream==%s' -T fields " \
                         "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport " \
                         "-e tcp.stream -e frame.time_epoch -e frame.time_delta_displayed -e ip.len -e tcp.payload" \
                         % (pcap_file_path, stream_index)

            result = run_tshark_command(tshark_cmd)
            formatted_result = format_tshark_results(result)

            pcap_file_name = Path(pcap_file_path).name

            stream = Stream(pcap_file_name, stream_index)
            stream_dict[(pcap_file_name, stream_index)] = stream

            i = 0
            pkt0_src_ip = ""
            pkt0_dest_ip = ""

            for line in formatted_result:
                try:
                    pkt = Pkt()
                    pkt.id = i
                    pkt.src_ip = line[0]
                    pkt.dest_ip = line[1]
                    pkt.src_port = int(line[2])
                    pkt.dest_port = int(line[3])
                    pkt.stream_index = int(line[4])
                    pkt.timestamp = float(line[5])
                    pkt.time_delta = float(line[6])
                    pkt.pkt_len = float(line[7])     # in rare cases, Thsark parsing results have incorrect data
                    pkt.payload_hex = line[8]
                    payload_formatted = pkt.payload_hex.replace(":","")
                    pkt.payload = bytes.fromhex(payload_formatted)

                    if pkt.id == 0:
                        pkt.direction = "up"
                        pkt0_src_ip = pkt.src_ip
                        pkt0_dest_ip = pkt.dest_ip
                    else:

                        if pkt.src_ip == pkt0_src_ip and pkt.dest_ip == pkt0_dest_ip:
                            pkt.direction = "up"
                        else:
                            pkt.direction = "down"

                    stream.pkts.append(pkt)
                    i += 1

                except:
                    msg = "[Warning] %s  stream %s pkt error" % (pcap_file_name, stream_index)
                    logger.warning(msg)
                    continue

            msg = "%s  stream %s [analyzed by tshark]" % (pcap_file_name, stream_index)
            logger.debug(msg)

        return stream_dict

    def generate_streams_feat(self, stream_dict):
        """
        Generate features for every TLS stream
        :return: stream_feat(list): list of features and
                                    every element represents the feature dict for the stream
        """

        feats = []

        for k, stream in stream_dict.items():
            feat = stream.generate_stream_features()    # feat in dict format
            feats.append(feat)

        return feats

    def save_feats(self, pcap_result_dict):
        """
        Save features as JSON files in self.output_dir with identical file stem with the pcap.
        :param pcap_result_dict(dict): pcap_feat_dcit
        :return: nothing
        """

        if self.output_dir == None:
            return

        p = Path(self.output_dir)
        if not p.is_dir():
            os.mkdir(self.output_dir, 0o755)

        output_dir_abs_path = os.path.abspath(self.output_dir)

        p = Path(pcap_result_dict[0]["pcap_name"])
        feat_file_name = p.stem + ".json"
        feat_file_path = os.path.join(output_dir_abs_path, feat_file_name)

        f = open(feat_file_path, "w")
        json.dump(pcap_result_dict, f, indent=4)
