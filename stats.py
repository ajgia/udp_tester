
# Imports
import pandas as pd
import numpy as np


# returns max sequence
def findMaxOfSequence(list, n):
    if not list:
        return 0

    s = set()
    for i in range(n):
        s.add(list[i])

    listMax = 0
    for i in range(n):
        if s.__contains__(list[i]):
            j = list[i]
            while (s.__contains__(j)):
                j += 1

            listMax = max(listMax, j - list[i])

    return listMax

# returns min sequence
def findMinOfSequence(list, n):
    if not list:
        return 0

    if len(list) == 1:
        return 1

    list.sort()

    shortestSequence = n
    currentSequence = 0
    inASequence = []

    for i in range(n):
        if i not in inASequence:

            currentSequence = 1
            j = i
            inASequence.append(i)

            while j < n - 1:
                if list[j] + 1 == list[j + 1]:
                    currentSequence += 1
                    inASequence.append(j+1)
                j += 1


            i = j
            if currentSequence < shortestSequence:
                shortestSequence = currentSequence

    return shortestSequence



# Import data and name columns
data = pd.read_csv('./log.csv', header=None)
data.columns = ['packet_id', 'max_packets', 'ip', 'port']

# split data by client (same IP + same Port)
groupedBy = data.groupby(['port', 'ip'], sort=False)

# extract keys from groups
keys = groupedBy.groups.keys()

# aggregate variables
total_missing = 0
min_lost = 9999999999
max_lost = 0
min_unordered = 9999999999
max_unordered = 0
total_unordered = 0


# process groups  
for i in keys:
    print('client: ' + str(i))
    group = groupedBy.get_group(i)
    group.reset_index(drop=True, inplace=True)
    print(group)
    print ('\n')
    packetsReceived = len(group.index)
    packetsIntended = group.iloc[1]['max_packets']
    packetsLost = packetsIntended - packetsReceived
    total_missing += packetsLost
    print('num packets received: ' + str(packetsReceived))
    print('num packets intended: ' + str(packetsIntended))
    print('packets lost: ' + str(packetsLost))

    # make a series for faster processing
    receivedSeries = pd.Series(data = group['packet_id'], index=list(range(0, packetsIntended)))
    expectedSeries = pd.Series(range(1, packetsIntended + 1))
    expectedSeries.rename('packet_id')

    # find missing and out of order packets
    lastVal = 0
    val = 0
    missing = []
    out_of_order = []
    visited = []
    full = list(range(1, packetsIntended + 1))

    for index, value in receivedSeries.items():
        lastVal = val
        val = value

        visited.append(val)

        # found out of order number
        if val != lastVal + 1 and np.isnan(val) == False:
            out_of_order.append(val)

    out_of_order.sort()

    # print packets lost and out of order
    if packetsLost != 0:
        missing = list(set(full).difference(set(visited)))
        print('lost packet ids: ' + str(missing))
    lost_max = findMaxOfSequence(missing, len(missing))
    lost_min = findMinOfSequence(missing, len(missing))
    print('min # packets lost in sequence: ' + str(lost_min))
    print('max # packets lost in sequence: ' + str(lost_max))
    print('out of order packet ids: ' + str(out_of_order))
    out_of_order_min = findMinOfSequence(out_of_order, len(out_of_order))
    out_of_order_max = findMaxOfSequence(out_of_order, len(out_of_order))
    print('min # packets out of order in sequence: ' + str(out_of_order_min))
    print('max # packets out of order in sequence: ' + str(out_of_order_max))

    # debug only: compare function for verification
    # comparison = receivedSeries.compare(expectedSeries)
    # if len(comparison) != 0:
    #     print('\nself = received, other = expected')
    #     print(comparison)

    ## update aggregate variables
    total_unordered += len(out_of_order)
    if lost_min < min_lost:
        min_lost = lost_min
    if lost_max > max_lost:
        max_lost = lost_max
    if out_of_order_min < min_unordered:
        min_unordered = out_of_order_min
    if out_of_order_max > max_unordered:
        max_unordered = out_of_order_max


    print('\n\n')

    
print('--------AGGREGATE STATISTICS--------')
average_missing = round(total_missing / groupedBy.ngroups, 2)
average_unordered = round(total_unordered / groupedBy.ngroups, 2)
print('average lost: ' + str(average_missing))
print('max lost: ' + str(max_lost))
print('min lost: ' + str(min_lost))
print('average out of order: ' + str(average_unordered))
print('max out of order: ' + str(max_unordered))
print('min out of order: ' + str(min_unordered))


