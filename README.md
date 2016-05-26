The broker policy here works with the host cluster analyzers provided by the other code, but exist as a pair of *separate* bro processes.

Here you would have:

broctl run manager/proxy/isshd/syslog/auditd etc

bro broker_front
bro broker_back

The cluster bro members will interact with the broker repo via the broker_front using a regular bro <-> bro TCP socket.  In the front end the long term data interface lives where the cluster members can address user data more or less transparently.  The back end (broker_back) is just a sqlite instance for perminant storage.
