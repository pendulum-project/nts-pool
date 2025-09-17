# Time source weighting

Individual time sources in the pool are given weights, which are used to distibute load to time sources whilst keeping in mind the different amounts of load individual time sources can manage. The goal of the load balancing algorithm is to distribute load over time sources such that the number of client requests assigned to each server is roughly proportional to its weight. So if time source A has weight 1, and time source B has weight 2, the intent is for time source B to receive twice as many requests as time source A.

There are practical factors that limit the effectiveness of this. First, time sources are assigned randomly, and even if the chance of drawing each server is perfectly proportional, random variation will cause slight imbalances. These get smaller in relative terms with more requests.

Second, clients can indicate they already have certain time sources. In that case, these time sources are excluded initially during the random drawing process. This also produces deviations from the ideal ratios, especially if there are few time sources with large weight but many with smaller weights.

# Implementation

The drawing of a random time source is done by adding up the total weight of all time sources in the region used to serve the request, and then drawing a random number between 0 and that total weight. Then, the list of time sources is considered one by one, adding their weights, until the result of addition becomes larger than the random number.

This process is accelerated by using a precalculated list of sums of weights for the time sources, and using binary search to find the selected time source. In case this was a time source that the client explicitly excluded, we add it to an exclusion list of time sources to ignore in next selections. Some calculation is then used to exclude it in the next draw, whilst still allowing use of the pre-calculated list. If multiple draws don't result in a success, on the final iteration (4th or the size of the region currently) a source is returned from the servers not previously excluded regardless of whether the client has indicated it doesn't want it.
