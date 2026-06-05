This week I created and tested two custom Suricata rules to detect suspicious network behaviour. The first rule was made to detect TCP SYN scanning against the protected network. This type of scan is usually used in the reconnaissance stage of an attack because it helps an attacker find open ports before trying anything else. The second rule was made to detect repeated SSH attempts to port 22. This kind of behaviour can suggest brute-force login attempts or repeated unauthorised access, so it was a useful second detection case for this lab.

The threshold logic was important because the rules needed to detect suspicious activity without creating too many unnecessary alerts. For the SYN scan rule, the threshold was tracked by source IP so repeated packets from the same scanner were counted together instead of creating an alert for every single packet. I tested different count values to see how the alerts changed. A lower threshold made the rule more sensitive, while a higher threshold reduced alert noise. In my lab, even when I increased the threshold, the full-port SYN scan still produced alerts because the scan volume was high enough to cross the stricter setting. For the SSH rule, I used a threshold of 10 attempts in 30 seconds so that normal login mistakes would not trigger immediately, but repeated rapid attempts from the same source would still be detected.

False positives were reduced by using thresholding and source-based tracking in both rules. This helped reduce alert flooding and made the rules more practical. For example, a normal user or administrator might type the wrong SSH password once or twice, but that should not be treated the same as repeated fast login attempts from the same IP address. In the same way, one SYN packet by itself is not enough to suggest a scan, but repeated SYN packets across many ports are much more suspicious. Because of this, the thresholds helped keep the rules realistic while still making the suspicious behaviour visible.
EOF>

>>EOF





