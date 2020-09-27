import json
import time
import os
import re
from kafka import KafkaProducer


class KafkaSender(object):
    def __init__(self, server, topic, label):
        self.server = server
        self.topic = topic
        self.producer = KafkaProducer(bootstrap_servers=[self.server],
                                      value_serializer=lambda m: json.dumps(m).encode('utf-8'))
        # 给发往kafka的每条数据打上标记，用于后续的过滤处理
        self.label = label

    # 发送指定文件数据
    def send_log_from_file(self, filepath):
        with open(filepath, "r", encoding="unicode_escape") as f_demo:
            for line in f_demo.readlines():
                line_clean = line.strip()
                if re.match("{.*}", line_clean):
                    log = eval(line_clean)
                    # log = line_clean
                    log['label'] = self.label
                    future = self.producer.send(self.topic, value=log, partition=0)
                    future.get(timeout=20)
                    time.sleep(0.2)  # avoid congestion
                    print(log)
                else:
                    # print(line_clean)
                    pass

    # 发送指定目录数据
    def send_log_from_dir(self, dirpath):
        for filename in os.listdir(dirpath):
            filepath = os.path.join(dirpath, filename)

            if os.path.isfile(filepath):
                print("===========================Sending file {}===================================".format(filename))
                self.send_log_from_file(filepath)


if __name__ == '__main__':

    # 初始化kafka producer
    # 这里需要指定自己的label
    kafka_sender = KafkaSender(server="10.99.216.80:30091",
                               topic="rsyslog",
                               label="lvhong")

    while True:
        # kafka_sender.send_log_from_dir("D:\log\\rsyslogbak")
        kafka_sender.send_log_from_file(filepath="demo_multi_window.txt")
        # time.sleep(10)
