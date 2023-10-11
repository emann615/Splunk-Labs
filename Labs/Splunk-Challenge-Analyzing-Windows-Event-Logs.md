# Splunk Challenge: Analyzing Windows Event Logs

## Desciption

In this lab, I will run through a scenario using Splunk to analyze Windows event logs and investigte a cyber attack.

## Table of Contents

   * [Languages and Utilities Used](#Languages-and-Utilities-Used)
   * [Environments Used](#Environments-Used)
   * [Walk-Through](#Walk-Through)

## Languages and Utilities Used

* **Splunk** 

## Environments Used

* **Ubuntu 18.04.6 LTS**

## Walk-Through

### Scenario

One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win_eventlogs** for further investigation.

**About the Network Information**

The network is divided into three logical segments. It will help in the investigation.

**IT Department**

* James
* Moin
* Katrina

**HR department**

* Haroon
* Chris
* Diana

**Marketing department**

* Bell
* Amelia
* Deepak

### Q1) How many logs are ingested from the month of March, 2022?

To find the number of logs ingested from March, I used the following query: `index=win_eventlogs date_month=march`

The results show 13,959 events for March.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/cb849140-7a50-4322-bb46-bc68544b68b5" height="50%" width="50%"/>
</br>
</br>

**A1) 13,595**

### Q2) Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

I selected the **UserName** field and saw there are 11 vlaues, but only the top 10 would show.

To see all 11 values, I hade to make a table of the user names.

I used the following search query: `index=win_eventlogs | dedup UserName | table UserName`
*	`dedup` removes duplicates.
*	`table` creates a table of the data.

After examining the table, I saw the user **Amel1a** is the imposter account.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/8c4a4a7e-d4c1-4158-bb9d-d742671fa8a7" height="30%" width="30%"/>
</br>
</br>

**A2) Amel1a**

### Q3) Which user from the HR department was observed to be running scheduled tasks?

I searched for schedueled task events using the following search query: `index=win_eventlogs schtasks`

I check the **UserName** field and saw **Chris.fort** was the only user listed from the HR department.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/65661a80-3048-4c41-b3c9-e9bbca015585" height="70%" width="70%"/>
</br>
</br>

**A3) Chris.fort**

### Q4) Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?

_Hint: Explore lolbas-project.github.io/ to find binaries used to download payloads_

To answer this question, I needed to create another table showing the **UserName** and **PorcessName** fields and filter for only the users in the HR department.

I used the following search query: `index=win_eventlogs UserName="Chris.fort" OR UserName="Daina" OR UserName="haroon" | dedup ProcessName | table UserName ProcessName`

After examining the poccesses, I found a process named **certutil.exe** that was executed by the user **haroon**.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/7cb21af7-f3c4-461e-8d50-0347f7090f3d" height="70%" width="70%"/>
</br>
</br>

I navigated to the link in the hint and search certutil.exe. It is a binary that is commonly used to download files.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/0ce5ebdb-9c95-41fa-910d-23bae9ae8d4a" height="70%" width="70%"/>
</br>
</br>

**A4) haroon**

### Q5) To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

In the previous step, I saw that the process used was **certutil.exe**.

**A5) certutil.exe**

### Q6) What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

To answer this question, I needed to add a time field to the table.

I used the following search query: `index=win_eventlogs UserName="Chris.fort" OR UserName="Daina" OR UserName="haroon" | dedup ProcessName | table _time UserName ProcessName`

Then, I was able to see the date and time the binary was executed in the left column of the table.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/ae4ae1c3-edce-482f-b1f6-f56e82a77c5b" height="80%" width="80%"/>
</br>
</br>

**A6) 2022-03-04**

### Q7) Which third-party site was accessed to download the malicious payload?

I filtered to show events for the user haroon and containing the key word certutil.exe using the following search query: `index=win_eventlogs UserName=haroon certutil.exe`

I checked the **CommandLine** field and was able to see the full command used to download the payload, including the domain name of third-party site.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/fdb04f11-b7f9-47f0-a2e7-4ca6494f0af9" height="70%" width="70%"/>
</br>
</br>

**A7) controlc.com**

### Q8) What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

I found the file name at the end of the command.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/4a17d39e-7db1-44fc-8a65-e7f58ab491bf" height="40%" width="40%"/>
</br>
</br>

**A8) benign.exe**

### Q9) The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

I navigated to the URL in the command and found the flag.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/63e450e4-723d-47b1-953a-92b0e208f3a9" height="30%" width="30%"/>
</br>
</br>

**A9)** THM(KJ&*H^B0)

### Q10) What is the URL that the infected host connected to?

The URL was also in the command.

<img src="https://github.com/emann615/Investigating-with-Splunk/assets/117882385/78abb212-a575-4d44-9084-9b43767c2fda" height="40%" width="40%"/>
</br>
</br>

**A10) https://controlc.com/548ab556**

