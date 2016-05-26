The broker policy here works with the host cluster analyzers provided by the other code, but exist as a pair of <b>separate</b> bro processes.

Here you would have the "normal" bro cluster:

broctl run (manager/proxy/isshd/syslog/auditd) etc

at the same time as having two independent bro instances for the broker infrastructure.

bro broker_front
bro broker_back

The cluster bro members will interact with broker via event sharing to the broker_front. In the front end the long term data interface lives where the cluster members can address user data more or less transparently.  The back end (broker_back) is just a sqlite instance for permanent storage.
