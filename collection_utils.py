from collections import Counter

def find_most_common_entries(some_collection):
  '''Returns a tuple containing a list with the entries with maximum cardinality and the maximum cardinality.'''
  counter = Counter(some_collection).most_common()
  max_cardinality = counter[0][1]
  return ([ a[0] for a in counter if a[1] == max_cardinality ], max_cardinality)
