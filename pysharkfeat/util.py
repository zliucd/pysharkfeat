"""
GPL V3 license

Copyright (C) 2022 Zhi Liu<cowliucd@gmail.com>

util.py
This file is part of Pysharkfeat, a feature extraction tool from encrypted traffic. See LICENSE for more information.

"""

import subprocess, os
from tempfile import NamedTemporaryFile

def run_tshark_command(cmd_str):
    """
    Run tshark command and return results
    :param cmd_str(str): tshark command line
    :return: result(str): result from tshark,
                          raw outputs if successfully executed, otherwise none.
    """

    f = NamedTemporaryFile("w+t")
    full_cmd = cmd_str + " > " + f.name

    ret = os.system(full_cmd)

    if ret == 0:
        result = f.readlines()
    else:
        result = None

    f.close()

    return result

def test_tshark():
    """
    Test if tshark can be called by command line.
    Raise exception if tshark is not installed or cannot be called by command.
    :return: nothing
    """

    try:
        subprocess.run(["tshark", "--version"], stdout=subprocess.PIPE)
    except:
        raise Exception("[Error] Test tshark error, you may need to install Wireshark and make sure tshark can be called by command line.")


def format_tshark_results(lines):
    """
    Format tshark outpug.
    :param lines(str): raw result from tshark
    :return: new_lines(str): formatted result
    """

    new_lines = []

    for line in lines:
        tmp = line.replace("\n","")
        elements = tmp.split("\t")
        new_lines.append(elements)

    return new_lines


def precify_float(x):
    """
    Precify float to certain digits(default eight)
    :param x(float): input float
    :return: pricified float
    """

    return float("{:.8f}".format(x))
