import sys
from optparse import OptionParser
import matplotlib.pyplot as plt

# y is either the TP rate or the FP rate
# sampling_type: string that states the sampling type, used for label    
def graph(sampling_rate, y, sampling_type):
    plt.plot(sampling_rate, y)
    plt.xlabel('Sampling Rate')
    plt.ylabel(sampling_type)
    plt.show()


graph([1, 2, 3], [2, 3, 4], "test")
