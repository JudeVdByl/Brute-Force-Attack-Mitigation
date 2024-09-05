# Brute-Force Attack Mitigation

## Objective
Assist J&Y Enterprise in identifying and stopping a brute-force attack targeting their digital assets.

## Scenario Overview
J&Y Enterprise is one of the top coffee retailers, known for serving IT enthusiasts and tech geeks with unique coffee recipes. Their latest creation, "Shot4J," is stored in a highly protected digital safe. Recently, attackers have targeted J&Y’s assets in an attempt to steal this secret recipe. The company has hired me to secure their network from these threats.

## Tools Used
- **Snort**: Network intrusion detection system used to monitor and prevent attacks.
- **Linux**: Command-line environment for executing network monitoring tools.

## Steps to Mitigate the Attack

### Step 1: Analyze Traffic with Snort (Sniffer Mode)
- **Goal:** Identify the source, service, and port of the attack.
- **Action:** Start Snort in sniffer mode to monitor the traffic and observe any anomalies indicating a brute-force attack.
    ```bash
    sudo snort -c /etc/snort/snort.conf -v -d -i eth0 -K ASCII
    ```
![image](https://github.com/user-attachments/assets/71cf5a84-15d3-42d4-80c8-362c33c0a1d3)


### Step 2: Identify the Service and Port
- **Service Under Attack:** SSH
- **Protocol/Port:** TCP/22

### Step 3: Write an IPS Rule to Stop the Attack
- **Action:** Create a custom Snort rule to block the brute-force attack targeting SSH on port 22.
    ```bash
    Drop ip any any -> any 22 (msg: "IPS BRUTE-FORCE"; content: "loginfailed"; nocase; sid:100001; rev:1;)
    ```

### Step 4: Test the Rule
- **Action:** Test the rule using `-A console` mode to ensure it's detecting the attack.
    ```bash
    sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
    ```

### Step 5: Run Snort in IPS Mode to Block the Attack
- **Action:** After verifying the rule works, run Snort in IPS mode to block the attack for at least a minute. This will prevent further attempts and generate the flag.
    ```bash
   sudo snort -c /etc/snort/snort.conf -q -Q — daq afpacket -i eth0:eth1 -A console
    ```
![image](https://github.com/user-attachments/assets/4dfd1d87-bf68-44f3-9de1-20ce60296c25)

### Step 6: Retrieve the Flag
- **Action:** After successfully stopping the attack, the flag will appear on the desktop.

### Flag
- **THM{81b7fef657f8aaa6e4e200d616738254}**

![image](https://github.com/user-attachments/assets/1a46625d-36d0-45fc-a1d2-b485fb1c4060)



## Key Takeaways
- **Brute-force attack**: A common method used to guess credentials by trying multiple password combinations.
- **Service Targeted**: SSH service running on port 22 was the focus of the attack.
- **Snort in IPS Mode**: An Intrusion Prevention System (IPS) rule was crucial in blocking traffic and mitigating the threat.
- **Flag Retrieved**: After successfully stopping the attack, the flag was generated on the desktop, confirming the attack was blocked.
