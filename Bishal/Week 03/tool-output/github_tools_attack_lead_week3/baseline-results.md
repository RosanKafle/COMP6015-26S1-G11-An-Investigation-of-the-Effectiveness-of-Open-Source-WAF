# Week 3 DVWA Baseline Results

## sqlmap (Low Security)
- Command: sqlmap -u "..." --cookie placeholder
- Result: CRITICAL not injectable  
- Screenshot: [your terminal screenshots]
- Note: Needs real PHPSESSID cookie

## Manual SQLi (Firefox)
- Payload: id=1=1--
- Result: "First name: admin" SUCCESS
- Screenshot: [your DVWA screenshot]
