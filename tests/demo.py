from pysharkfeat.featextractor import FeatureExtractor
import json, os

# specify pcaps and output dir
pcap_dir = "./pcaps/2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap"
output_dir="./output"

extractor = FeatureExtractor(pcap_path=pcap_dir, output_dir=output_dir)
summary = extractor.main_extract_pcaps_feat()

print(summary)

# read feature files
feat_file = os.path.join(output_dir, "2021-01-04-Emotet-infection-with-Trickbot-traffic.json")
f = open(feat_file)
stream_feats = json.load(f)

for feat in stream_feats :
    print("%s,  stream_index:%s,  byte dist entropy:%s" % (feat["pcap_name"], feat["stream_index"], feat["bd_entropy"]))