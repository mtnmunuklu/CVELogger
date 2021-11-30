from src.config import Config
from src.app.logger import Logger
import logging
import requests as rq
import base64
import json
import zipfile

class NVD:
    """
    Tracks and logs CVs
    """
    def __init__(self):
        """
        Constructor Method
        :return: none
        """
        self.cve_file_prefix = Config.NVD_CVE_FILE_PREFIX
        self.cve_file_postfix = Config.NVD_CVE_FILE_POSTFIX
        self.cve_file_extension = Config.NVD_CVE_FILE_EXTENSION
        self.cve_file_name = self.cve_file_prefix + self.cve_file_postfix + self.cve_file_extension
        self.downloaded_dir = Config.DOWNLOADED_DIR
        self.cve_file_path = self.downloaded_dir + self.cve_file_name
        self.logger = Logger('NVD')


    def download_cves(self):
        try:
            r = rq.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
            r_file = rq.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + self.cve_file_name, stream=True)
            with open(self.cve_file_path, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)
        except Exception as e:
            self.logger.log(logging.ERROR, e) 


    def process_cves(self):
        try:
            archive = zipfile.ZipFile(self.cve_file_path, 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            # Iterate through each CVE in the feed
            for cve in cve_dict["CVE_Items"]:
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                cve_publish_date = cve["publishedDate"]
                # Parse out the CVE description
                for cve_desc_item in cve["cve"]["description"]["description_data"]:
                    if cve_desc_item["lang"] == "en":
                        cve_desc = cve_desc_item["value"]
                self.logger.log(logging.INFO, "ID={}, Publish Date={}, Description={}".format(cve_id, cve_publish_date, cve_desc))    
        except Exception as e:
             self.logger.log(logging.ERROR, e) 