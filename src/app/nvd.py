from src.config import Config
from src.app.logger import Logger
import logging
import requests as rq
import base64
import json
import zipfile
from nested_lookup import nested_lookup
from datetime import datetime

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
        self.execute_dates = Config.EXECUTE_DATES
        self.logger = Logger('NVD')

    # Download CVEs
    def download_cves(self):
        try:
            r = rq.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
            r_file = rq.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + self.cve_file_name, stream=True)
            with open(self.cve_file_path, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)
        except Exception as e:
            self.logger.log(logging.ERROR, e) 

    # Processes the already downloaded in json format CVEs
    def process_cves(self):
        try:
            archive = zipfile.ZipFile(self.cve_file_path, 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            cve_desc = ""
            cvssv3_score = 0
            cvssv3_secerity = ""
            cvssv2_score = 0
            cvssv2_secerity = ""
            # Iterate through each CVE in the feed
            last_execute_date = self.get_last_execute_date()
            for cve in cve_dict["CVE_Items"]:
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                cve_publish_date = cve["publishedDate"]
                cve_last_modified_date = cve["lastModifiedDate"]            
                if (last_execute_date != "" and self.is_new_cve(cve_last_modified_date, last_execute_date)) or last_execute_date == "":
                    # Parse out the CVE description
                    for cve_desc_item in cve["cve"]["description"]["description_data"]:
                        if cve_desc_item["lang"] == "en":
                            cve_desc = cve_desc_item["value"]
                    if "baseMetricV3" in cve["impact"]:
                        cvssv3_score = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                        cvssv3_secerity = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                    if "baseMetricV2" in cve["impact"]:
                        cvssv2_score = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        cvssv2_secerity= cve["impact"]["baseMetricV2"]["severity"]
                    # Parse out the vendors and products
                    vendors = self.convert_cpes(cve["configurations"])
                    self.logger.log(logging.INFO, "ID={}; Publish Date={}; Description={}; CVSSv3 Score={}; CVSSv3 Severity={}; CVSSv2 Score={}; CVSSv3 Severity={}; Vendors={}".format(cve_id, cve_publish_date, cve_desc,
                    cvssv3_score, cvssv3_secerity, cvssv2_score, cvssv2_secerity, str(vendors)))
            self.add_execute_date()
        except Exception as e:
             self.logger.log(logging.ERROR, e)


    def convert_cpes(self, conf):
        """
        This function takes an object, extracts its CPE uris and transforms them into
        a dictionnary representing the vendors with their associated products.
        """
        uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf

        # Create a list of tuple (vendor, product)
        cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

        # Transform it into nested dictionnary
        cpes = {}
        for vendor, product in cpes_t:
            if vendor not in cpes:
                cpes[vendor] = []
            cpes[vendor].append(product)

        return cpes

    def is_new_cve(self, last_modified_date, last_execute_date):
        last_modified_date = datetime.strptime(last_modified_date, '%Y-%m-%dT%H:%MZ')
        last_execute_date = datetime.strptime(last_execute_date, '%Y-%m-%dT%H:%MZ')
        if last_modified_date > last_execute_date:
            return True
        else:
            return False

    def get_last_execute_date(self):
        with open(self.execute_dates, "r") as file_object:
            lines = file_object.readlines()
        if len(lines) > 0:
            return lines[-1]
        return ""

    def add_execute_date(self):
        with open(self.execute_dates, "a") as file_object:
            file_object.write(datetime.now().strftime("%Y-%m-%dT%H:%MZ"))
    