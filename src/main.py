import sys
sys.path.append("../")
from src.app.nvd import NVD
import optparse

if __name__ == "__main__":
   desc = """This program tracks and logs CVs."""
   parser = optparse.OptionParser(version='%1.0', description=desc)
   parser.add_option('-s', '--Source', help='The source from which the CVEs were pulled.', dest='source', action='store', default="nvd", metavar='<ARG>')
   (opts, args) = parser.parse_args()
   if opts.source is None:
      parser.print_help()
   elif opts.source is not None and opts.source.lower() == "nvd":
      nvd = NVD()
      nvd.download_cves()
      nvd.process_cves()
   