import matplotlib.pyplot as plt

# y is either the TP rate or the FP rate
# sampling_type: string that states the sampling type, used for label    
def graph(sampling_rate, y, sampling_type, is_tp):
    plt.plot(sampling_rate, y)
    plt.xlabel('Sampling Rate')
    plt.title(sampling_type)
    if is_tp:
      plt.ylabel("True Positive Rate [%]")
    else:
      plt.ylabel("False Positive Rate [%]")
    plt.show()

# Graphs all 3 of the sampling methods in one plot!
# sampling_rate, y, and sampling_type are all arrays of the same size. Each
# is_tp is a bool that states if this is graphing the True Positive rate.
def graph_all(sampling_rate, y, sampling_type, is_tp):
  plt.xlabel('Sampling Rate')
  if is_tp:
    plt.ylabel("True Positive Rate [%]")
  else:
    plt.ylabel("False Positive Rate [%]")
  legend_arr = []
  for i in range(0, len(sampling_rate)):
    result = plt.plot(sampling_rate[i], y[i], label=sampling_type[i])
    legend_arr.append(result)
    plt.legend()
  plt.show()

#Testing
"""
graph([1, 2, 3], [2, 3, 4], "Uniform Sampling", False)
sampling_rate = [.1, .2, .5, .9, 1]
y = [[1, 2, 3, 4, 5], [2, 3, 4, 5, 6], [3, 4, 5, 6, 7]]
labels = ["Uniform Sampling", "Random 1 in N", "Systematic Sampling"]
graph_all([sampling_rate, sampling_rate, sampling_rate], y, labels, True)
"""
