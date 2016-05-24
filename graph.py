import sys
from optparse import OptionParser

# Reads in a file as a map of percentage_of_sample => {fp: x, tp: y}
# TODO
def read_file(filename):
    f = open(filename, 'r')

def main(argv, options):
    mp = read_file(options.filename)

if __name__ == "__main__": 
    parser = OptionParser()
    parser.add_option("-s", "--systematic", action="store_true", \
        help="Systematic Sampling", dest="systematic")
    parser.add_option("-r", "--random", action="store_true", \
        help="Random 1 in N Sampling", dest="random")
    parser.add_option("-u", "--uniform", action="store_true", \
        help="Random 1 in N Sampling", dest="uniform")
    parser.add_option("-f", "--file", \
        action="store", type="string", dest="filename")
    options, args = parser.parse_args()
    main(args[1:], options)
