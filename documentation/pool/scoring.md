# Time source scoring

The time source scoring algorithm is derived from that used in original NTP pool. 

It currently has the following rules
- Explicit denies get punished swiftly to unload a server (step of -10, max score of -50)
- No responses give step of -5
- Unsynchronized responses give step of -4, with punishment of max_score of -20 if it doesn't explicitly indicate it is unsynchronized.
- Linear scoring between 750ms offset and 100 ms offset, with step of -1 for 750 ms and step of0.5 for 100ms
- Linear scoring between 100ms offset and 25 ms offset, with step of 0.5 for 100ms and step of 1 for 25 ms
- Fixed step of 1 for offset less than 25 ms.
- Penalty of -1 added to the step if any of the ntp stages does not deliver the number of cookies requested.
