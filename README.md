# Pysharkfeat

**Pysharkfeat** is a TLS encrypted traffic feature extraction tool from pcaps written in Python by using Wireshark's command line ```tshark```. 

Pysharkfeat is derived from an academic research on [malicious encrypted traffic analysis](https://www.yurenliu.com/research). Compare with other feature extraction tools such as [Flowmeter](https://github.com/ahlashkari/CICFlowMeter) and [Joy](https://github.com/cisco/joy), Pysharkfeat is easier to setup and use while providing rich features.


### Features
 - Parse a single pcap or directory to generate meta and statistical features
 - Export features in JSON files
 - Support logging 

**Traffic features include**:

 - **Meta**: 5-tuple(src ip, src port, dest ip, dest port, timestamp), duration, stream index
 - **Statistical**: 
     - Bidirectional packet len and inter-arrival-time sum/max/min/mean/std
     - SPLT(Markov sequence of pkt len and time) 
     - Byte distribution, payload std and entropy.
 - **TLS**: todo. 

 Full features can be found in ```feat.py``` or feature JSON file.

 ### Environment
- Language: Python3.8, 3.9  
- Dependence: Wireshark


### Installation
Install pysharkfeat from pip

``` pip3 install pysharkfeat ```

Install Wireshark(tshark)

 - Windows/Mac: https://www.wireshark.org/#download 
 - Centos: ``` sudo yum install wireshark```
 - Ubuntu: ``` sudo apt-get install wireshark ```


Test  tshark

``` tshark --version```

For Windows, make sure tshark can be called by command line by adding ```tshark``` to the environment path.

### Use case

Pysharkfeat can be used for machine learning research and threat analysis. 

There are several feature files in ```tests/output``` generated from pcaps at [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/2021/index.html), and you can immediately start analyzing them.

### Example

This code snippet can be found in ```tests/demo.py```. 

```python
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


# display stream index and byte distribution entropy features, and bd entropies are very close.

    2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap,  stream_index:3,  byte dist entropy:7.999464797314957
    2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap,  stream_index:7,  byte dist entropy:7.903172099500442
    2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap,  stream_index:9,  byte dist entropy:7.9876935373284805
    ...

```

### Performance consideration

#### Time
Pysharkfeat is built on tshark, which may incur substantial overhead. The following table shows some test results on a Mac OSX(CPU i5, 16GB RAM).

| pcap name                                                | pcap size | num of TLS streams | time(sec) |
|----------------------------------------------------------|-----------|--------------------|-----------|
| 2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap | 5.4MB     | 10                 | 10.8      |
| 2021-01-05-PurpleFox-EK-and-post-infection-traffic.pcap  | 9.5MB     | 8                  | 11.5      |
| 2021-01-15-Emotet-epoch-1-infection-traffic.pcap       | 5.9MB     | 40                    | 38.2      |
| 2021-02-24-Qakbot-infection-with-spambot-traffic.pcap    | 21.1MB    | 94                 | 213.9     |

#### Storage
The feature file of a single TLS stream has approximately 16KB. If a pcap has 100 TLS streams, the storage will be roughly 1.6MB.

### Feedback
You are welcome to post a issue or feature request, or send email to the author <zliucd66@gmail.com>. 

### License 
Pysharkfeat is open source and free to use under GPL V3 license. See LICENSE for more details.




