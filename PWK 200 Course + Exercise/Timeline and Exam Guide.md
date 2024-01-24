| Date | Task | Daily Routine | Daily Study plan |
| ---- | ---- | ---- | ---- |
| 20th Jan to 31th Jan | Complete all modules (80% Exercise Each Module) | 1 Hours + Remaining Hours for Content | Up to 3 am Morning |
| 1st Feb to 10th Feb | Content Revision, PWK lab, Proving Ground | Content Revision (2 hours), PWK lab (7 hours ), Proving Ground (6 hours ) - Minimum 30 machine from offsec and all TJ null list proving play and practice | 10 am - 12 pm, 12 pm - 8 pm, 8 pm - 3 am |
| 11th Feb to 21st Feb | PWK Revision + Attempting new challengs from offsec lab | PWK Revision (8 hours) + Attempting new challengs from offsec lab (8 hours) | 10 am - 6 pm, 6 pm - 3 am  |


## Exam Guide

| Topics | Details |
| ---- | ---- |
| Exam Duration | 23 hours and 45 minutes |
| Documentation time | Next 24 hours, submit files within that time |
| Proctored FAQ | https://help.offensive-security.com/hc/en-us/sections/360008126631-Proctored-Exams |
| Structure | 60 Points (3 independent targets worth 20 points each, 10 for low and 10 for priesc), 40 points (2 clients with 1 domain controller, no partial points) |
| Passing marks | 70 points |
| Machine objectives | Located in exam control panel |
| Documentation Requirements | Must document all attacks including all steps, commands issued, and console output in the form of a penetration test report. Through enough that the attacks can be replicated step-by-step by a technically competent reader. |
| Documentation disclaimer | Only one submission/attempt is allowed, zero points for missing screenshots and information. |
| Exploit Code | Only URL if modifications have not made, otherwise document as per guidelines with details information https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide |
| Exam proofs | Each target machine contains at least one proof file (local.txt or proof.txt). The valid way to provide the contents of the proof files is in an interactive shell on the target machine with the 'type' or 'cat' command from their original location. To receive full points, windows machine must have a shell  with permission or either SYSTEM user, Administrator user or User with Administrator privileges. To receive full points, Linux machine must have a shell with permission of root. |
| Control Panel Submission | Contents of the local.txt and proof.txt files obtained from your exam machines must be submitted in the control panel before your exam has ended, it will not indicated whether submitted proof is correct or not. |
| Screenshot Requirements  | Screenshot should display obtained hashes along with IP address of that  machine.   |
|  |  |

## Exam Restrictions 

1. Spoofing (IP, ARP, DNS, NBNS, etc.)
2. Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
3. Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
4. Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
5. AI chatbots (e.g. ChatGPT, YouChat, etc.)
6. Features in order tools that utilize either forbidden or restricted exam limitations 
7. Metasploit modules (Auxiliary, Exploit and Post) or meterpreter payload can only use against one single target machine either you succeed or not on it. 
8. Metasploit cannot be used for pivoting 

## Tools that are allowed (Confused ones only)
1. Nmap and its scripting engine
2. Nikto
3. Brup Free
4. Dirbuster
5. Multi handler (aka exploit/multi/handler) and msfvenom for all machines
## VPN Connection

A vpn connection file will be provided during the exam which needs to be used with openvpn for vpn connection. 

## Machine Revert

24 Reverts limitations. Only revert if required and check the machine after reverting, you will lose the working file in it after reverting. 

## Exam Proof File Names 

Proof.txt (only accessible to the root or administrator user) and Local.txt (File is accessible to an unprivileged user account)

## Point Disqualification

Restricting tool usages, metasploit and meterpreter usages in multiple machines, local.txt or proof.txt without an interactive shell screenshot and lack of documentation 

## Suggested Documentation Templates

[https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) 

## Bonus Points 

80% of correction solutions in every module’s lab and 30 correct proof.txt hashes from the challenge labs (It is important to submit both local.txt and proof.txt where applicable).

## Contact Protocol 

Contact live chat in case of any need but do not expect any hints. 

## Submission Instructions

PDF format, name format "OSCP-OS-XXXXX-Exam-Report.pdf", archived with .7z file from kali machine without password, not more than 200 mb, upload .7 file at [https://upload.offsec.com](https://upload.offsec.com), check md5 hash of local and uploaded file, will receive confirmation email after submitting file. 

## Results 

Expect within 10 business days.
