from pcapfile import savefile
import pyshark
import sys

def main(argv):
  if len(argv) < 1:
    print "Error: please pass in pcap file."
    sys.exit(1)
  testcap = open(argv[0], 'rb')
  capfile = savefile.load_savefile(testcap, verbose=True)
  print capfile
  cap = pyshark.FileCapture(argv[0])
  print cap


if __name__ == '__main__':
  main(sys.argv[1:])
