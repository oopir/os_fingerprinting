# Machine Learning Model for Passive OS Fingerprinting
OS fingerprinting is the process of detecting a remote server's OS (and version) by communicating with it and analyzing its response. This process is important for security experts (and attackers), since knowing a server's OS reveals the server's security vulnerabilities. <br/>

The most common  tools for fingerprinting (Nmap, NetworkMiner, Satori, p0f) rely on a database of "network signatures" (a signature can be thought of as the 'accent' or 'body language' of an OS). The database is maintained manually by security experts, and has not been updated in a long time (most tools rely on the database of p0f).<br/>

This project is an attempt to create an ML model for OS fingerprinting.

## Background on OS Fingerprinting
There are 2 types of fingerprinting:<br/>
- **Active** fingerprinting takes advantage of known security flaws: if there was a vulnerability in version X of the linux kernel, and it was fixed in version Y, then attempting to use the exploit will help us determine the server's kernel version ("exploit completed successfully" --> "server has version X"). Nmap is a common tool for active fingerprinting.<br/>

- **Passive** fingerprinting only analyzes packets of 'typical/legitimate' communication (mainly the TCP/IP headers). p0f is a common tool for passive fingerprinting.<br/>

The trade-off between the two methods: the active method has better accuracy, but its 'aggressive' nature makes it much easier to detect by firewalls.<br/>

In this project my models perform the passive version. To be precise, they only look at the server's TCP SYN-ACK message, which makes the process extremely stealthy and fast.<br/>

*Related Work*: I found a paper written by IEEE researchers about a similar project:<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[A Machine Learning-based Tool for Passive OS
Fingerprinting with TCP Flavor as a Novel Feature](https://www.duo.uio.no/bitstream/handle/10852/83660/Final_Desta_A_Deep_Learning_based_Universal_Tool_for_Operating_Systems_Fingerprinting_from_Passive_Measurements.pdf?sequence=2&isAllowed=y)
<br/><br/>

## Data Generation
I collected data on ~1,000,000 servers (chosen from a list of popular websites).<br/>

### *Establishing Ground Truth*
Since I don't have a datacenter's-worth of my own servers, finding labeled servers felt like a 'chicken and egg' problem. I decided to use Nmap's analysis as my ground truth: it may not be 100% accurate, but it does harness the percision of *active* fingerprinting, and it's an industry standard.<br/>

Nmap's output usually claims to be of 85%-90% certainty. It returns a list of guesses in descending order of certainty. For this reason I aimed for 85%-90% accuracy with my models, and decided that the most relevant accuracy metric will be top-2 accuracy. 
<br/>

### *Feature Selection*
I chose the features by reading [p0f's documentation](https://lcamtuf.coredump.cx/p0f3/README), the [paper mentioned before](https://www.duo.uio.no/bitstream/handle/10852/83660/Final_Desta_A_Deep_Learning_based_Universal_Tool_for_Operating_Systems_Fingerprinting_from_Passive_Measurements.pdf?sequence=2&isAllowed=y) and the [RFC on TCP/IP headers](https://datatracker.ietf.org/doc/html/rfc4413#section-4.3).<br/>
Some of the most helpful fields are IP's "Dont Fragment" flag, IP's TTL value, TCP's MSS value, and TCP's options. 
<br/>

### *Data Collection*
The process of retrieving labels and the process of retrieving features were run separately using different tools.<br/>

Label retrieval: Python has a wrapper for Nmap, so automating the scan was relatively trivial. Another advantage of Nmap is a built-in ability to concurrently scan multiple hosts.<br/>

Feature retrieval: to analyze a server's SYN-ACK message, I sent an HTTP request while sniffing the communication with Scapy (a sniffer & packet manipulation tool). I used multithreading to probe multiple hosts simultaneously.<br/>
(Initially I only sent a TCP SYN message, as it's simpler & faster than sending a full HTTP request. I noticed there was almost no variety in the response's TCP options, and suspected it may be due to the 'synthetic' nature of the probe. Switching to a full HTTP request resulted in the variety I was hoping for.)<br/>

My scan found the following operating systems:<br/>
<div align='center'>

| OS            | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   # Samples &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| OS            | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  # Samples &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| :-----------: |:------------------------------------------------------------------------:| :-----------: |:------------------------------------------------------------------------:|
| Linux 5.X     | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   12392     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| OpenBSD 4.X   | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  7041      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| Linux 4.X     | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   110824    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| FreeBSD 6.X   | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  72072     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| Linux 3.X     | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   88485     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| embedded      | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  76809     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |
| Linux 2.6.X   | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   50978     &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| Windows 2016  | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  6224      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | 
| Linux (Other) | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   5634      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| Windows 2012  | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  9014      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; |

</div>
<br/><br/>

## Model Comparison
The *Models*:<br>
* *SVM*: in some of the features, different operating systems result in different value *ranges* (for example, Windows systems tend to have initial TTL of 128, while Linux systems tend to have initial TTL of 64). I believed this property might call for a linear classifier.

- *Gradient Boosting*: this is simply a typical choice for tabular data.

- *Neural Network*: adding this model was mostly for my own curiosity. The network has 4 fully-connected layers.
<br/><br/>

The *Metric*: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;As I wrote under *Establishing Ground Truth*, the metric that fit my data is top-2 accuracy. <br/>
&nbsp;&nbsp;&nbsp;&nbsp;Note that it does not hinder user experience too much: receiving 2 guesses isn't so bad when looking for exploits.<br/><br/>

The *Results*: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;All 3 models reached a top-2 accuracy of around 85%.    Graphs are available in the Model Training Notebook.