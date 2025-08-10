# SETUP-and-CONFIGURATION-of-the-FIREWALL
Securing network endpoints by implementing and testing host-based firewall policies. This project involved configuring UFW on Kali Linux and Windows Defender Firewall to filter traffic, block vulnerable ports, and establish a secure baseline in a virtualized environment.










**WINDOWS FIREWALL**
 --------------------------------
![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/f2767fde407cac42ae70455c43ac29c0e87460c0/Screenshot%202025-08-09%20121352.png)

# Windows Firewall Inbound Rules Explained
*[HERE NO EXTRA INBOUND RULES WERE ADDED]*

This document explains the provided screenshot, which shows the **Windows Defender Firewall with Advanced Security** management console. Specifically, it details the list of configured **Inbound Rules**.


---

## What are Inbound Rules?

Think of your computer's firewall as a digital bouncer for your network connections. By default, it blocks all unsolicited incoming traffic to keep your system secure.

An **inbound rule** is a specific exception to this default policy. It tells the firewall, "It's okay to let traffic in if it meets these exact criteria." These rules are essential for applications that need to act as a host or server, receiving connections from other devices on your local network or the internet.

Common reasons for inbound rules include:
* Hosting a game server for friends to join.
* Using peer-to-peer (P2P) applications.
* Streaming media from your PC to another device (like a TV or console).
* Running local development servers that need to be accessed by other devices.

---

## Decoding the Rules Table

Each row in the list is a distinct rule. Here’s a breakdown of the key columns:

| Column          | Description                                                                                                                                    |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name** | A human-readable name for the rule, usually the name of the application like `brave.exe`.                                                        |
| **Profile** | Defines when the rule is active: `Public` (untrusted networks), `Private` (home/work networks), `Domain` (corporate networks), or `All`.          |
| **Enabled** | `Yes` means the rule is active. `No` means it is currently disabled.                                                                           |
| **Action** | The core function of the rule: ✅ **`Allow`** permits the connection, while ❌ **`Block`** would deny it.                                         |
| **Program** | The full path to the executable file (`.exe`) that the rule applies to.                                                                        |
| **Protocol** | The network protocol, most commonly `TCP` (reliable, for web/files) or `UDP` (fast, for streaming/gaming).                                       |
| **Remote Address**| Specifies which remote IP addresses are allowed to connect. `Any` means a connection from any device is permitted by this rule.                |

---

## Analysis of This Configuration

The rules shown in the screenshot are typical for a modern Windows PC. We can infer the following about the system:

* **Third-Party Security:** The user has `360 Total Security` installed, which has automatically added rules to allow its components to communicate.
* **Web Browsers:** Rules for `Brave` and `Firefox` exist, likely to support features like WebRTC (for in-browser video/audio calls) or peer-to-peer data sharing.
* **Productivity & Entertainment:**
    * `Microsoft Office Outlook` has a rule to receive email from a mail server.
    * `NVIDIA SHIELD Streaming` rules are enabled, indicating the user streams games or media from this PC to an NVIDIA SHIELD device.
* **Development:** The presence of `Visual Studio Code` suggests software development activity, where a rule is needed for features like remote debugging or live server previews.

Notably, all the rules shown appear to be legitimate entries created automatically by the software installers themselves (e.g., NVIDIA, 360 Total Security, Brave). **There are no signs of unusual or manually added custom rules**, suggesting a standard and clean firewall configuration based on the installed applications.

In essence, this screen provides a transparent view of which applications on this PC have been authorized to accept incoming network connections, acting as a critical control panel for network security.

--------
![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/f2767fde407cac42ae70455c43ac29c0e87460c0/Screenshot%202025-08-09%20121730.png)

# Verifying a Firewall Block Rule

This document demonstrates how to test if a firewall "Block" rule is working correctly.

### 1. The Setup

An inbound rule was added to the Windows Defender Firewall to explicitly **Block** all incoming connections on **TCP Port 23** (the default port for Telnet).

 

***

### 2. The Test

To verify the rule, the `Test-NetConnection` command was run in PowerShell. This command attempts to establish a TCP connection to port 23 on the local machine (`localhost`).

```powershell
Test-NetConnection -ComputerName localhost -Port 23
```
*THE RESULT*
The command fails as expected , and the output below confirms that the connection was blocked by the fire wall
```powershell
WARNING: TCP connect to (::1:23) failed
WARNING: TCP connect to (127.0.0.1:23) failed

ComputerName           : localhost
RemoteAddress          : ::1
RemotePort             : 23
InterfaceAlias         : Loopback Pseudo-Interface 1
SourceAddress          : ::1
PingSucceeded          : True
PingReplyDetails (RTT) : 0 ms
TcpTestSucceeded       : False
```
The final line, TcpTestSucceeded: False, is the crucial piece of information. It provides definitive proof that the firewall rule is active and successfully preventing TCP connections to port 23. The PingSucceeded: True result is also expected, as the rule only blocks the TCP protocol, not the ICMP protocol used by ping.

-------------------

![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/f2767fde407cac42ae70455c43ac29c0e87460c0/WhatsApp%20Image%202025-08-09%20at%209.13.42%20PM%20(2).jpeg)
*Network Share Access: Port 445 Open*

This document explains the expected behavior when you try to access a Windows network share and its file-sharing port is correctly open.

 

### What Is Happening Here?

1.  **Successful Connection:** You are attempting to connect to another computer on your network at the IP address `10.140.63.116`. Because **Port 445** (used for Windows File Sharing, or SMB) is **open** on that target machine, your computer successfully established a network connection. The firewall on the remote PC allowed your request.

2.  **Authentication Prompt:** After the connection is made, the remote computer asks for credentials ("User name" and "Password"). This is a crucial security step. It's not a connection error; it's the system asking, "You've reached me, but who are you, and do you have permission to access my files?"

3.  **Authentication Failure:** The error message, **"The username or password is incorrect,"** means the authentication step failed. The credentials you provided don't match an authorized user account on the target machine (`10.140.63.116`).

***

### Key Takeaway

This scenario demonstrates a **successful network connection** followed by a **failed user authentication**. This is the correct and secure process for accessing a network share. If Port 445 had been blocked by a firewall, you would not have even seen the credential prompt; you would have received a network error instead.

-------------------------------------

![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/f2767fde407cac42ae70455c43ac29c0e87460c0/Screenshot%202025-08-09%20124032.png)
# Custom Firewall Rule: Blocking Port 445 (SMB)

This document explains a custom inbound firewall rule designed to block Windows File Sharing.

 

***

### Rule Analysis

The highlighted rule, named **"BLOCKING PORT 445 (SMB)"**, is a manually created security policy. Its primary purpose is to prevent other computers on the network from initiating file and printer sharing connections with this PC.

***

### Key Properties Breakdown

* **Action:** The rule's action is set to **`Block`**, which instructs the firewall to actively refuse any incoming traffic that matches the rule's criteria.
* **Protocol and Port:** It specifically targets **TCP Port 445**. This is the standard port used by the Server Message Block (SMB) protocol for all modern Windows file and printer sharing.
* **Profile:** By being set to **`All`**, this rule remains active across all network types—Private (home/work), Public (café/airport), and Domain (corporate).
* **Enabled:** The status is **`Yes`**, confirming that the rule is currently active and being enforced by the firewall.

***

### Impact of This Rule

With this rule enabled, any external device attempting to access shared folders or printers on this machine will be denied at the network level. The connection will fail before any authentication can take place. Instead of a login prompt, the user trying to connect will typically encounter a network error, such as "Windows cannot access [PC-Name]" or a connection timeout.

-------------------------------------
![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/f2767fde407cac42ae70455c43ac29c0e87460c0/WhatsApp%20Image%202025-08-09%20at%209.13.42%20PM%20(1).jpeg)
# Result of Blocking Port 445: Sharing Unavailable

This document shows the direct consequence of activating the firewall rule to block SMB port 445.

### The Connection Attempt

To test the block, a connection was attempted from another computer. The standard UNC path **`\\10.140.63.116\c$`** was entered into File Explorer. This path is used to access the hidden administrative C: drive share on the target machine.

### The Inevitable Network Error

Because the firewall rule is actively **blocking all incoming traffic on Port 445**, the connection attempt fails immediately at the network level. The result is the "Network Error" message shown below.
 

The error "Windows cannot access \\10.140.63.116" is the expected outcome. The firewall is successfully preventing the SMB protocol from establishing a connection, making all file shares on the machine completely unavailable from the network.

***

### Conclusion

This confirms that the firewall rule works exactly as intended. By blocking port 445, you effectively disable all network access to the computer's shared folders and drives, which is a common security hardening step. The system no longer even presents a login prompt because the underlying network connection is refused.


--------------------------------
**LINUX FIREWALL**



![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/main/Screenshot%202025-08-09%20140606.png)
# UFW: The Uncomplicated Firewall for Linux

**UFW**, which stands for **Uncomplicated Firewall**, is a user-friendly command-line interface for managing the Netfilter firewall on Linux. It's designed to simplify the process of configuring firewall rules, acting as an easier-to-use frontend for the powerful but complex `iptables` backend. UFW is the default firewall management tool on Ubuntu and its derivatives.

***

### Core Concepts

* **Default Policy**: UFW is secure by default. It is configured to **deny all incoming** connections and **allow all outgoing** connections.
* **Simple Syntax**: It uses straightforward commands that are easy to remember (e.g., `ufw allow ssh`).
* **Application Profiles**: Many common applications (like web servers or databases) provide UFW profiles upon installation, which pre-define the necessary firewall rules.

***

### Common UFW Commands

Here are the most essential commands for managing your firewall with UFW.

```bash
# Check the firewall's status and current rules
sudo ufw status verbose

# Enable or disable the firewall (it starts on boot if enabled)
sudo ufw enable
sudo ufw disable

# Allow incoming traffic by service name, port, or profile
sudo ufw allow ssh          # Allows traffic on port 22/tcp
sudo ufw allow 443/tcp      # Allows HTTPS traffic
sudo ufw allow 'Nginx Full' # Allows traffic via an application profile

# Deny incoming traffic on a specific port
sudo ufw deny 8080

# Delete a previously added rule
sudo ufw delete allow 443/tcp
```

 -----------------

## Testing a UFW Firewall from a Host Machine

This document explains a scenario where a Linux virtual machine's firewall (`ufw`) is tested from its Windows host machine. The resulting connection failure confirms that the firewall is operating correctly.

![Testing UFW Firewall from Windows to a Linux VM](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/main/Screenshot%202025-08-09%20141841.png)

***

### Linux VM Firewall Configuration (`ufw`)

The terminal on the left shows the configuration of the firewall on the Linux guest system. The most critical setting is its default policy:

* **`Default: deny (incoming)`**

This means that unless a rule is created to **explicitly allow** traffic on a specific port, all incoming connections will be automatically blocked. Since there is no `allow` rule for port 23 (Telnet), the firewall will deny any attempt to connect to it.

***

### Windows Host Connection Attempt

The Command Prompt on the right shows the connection attempt from the Windows host to the Linux VM (at the IP address `10.0.2.15`).

The command `telnet 10.0.2.15 23` is used to try and open a connection on the Telnet port. The result is:

* **`Could not open connection to the host...Connect failed`**

This is not a network error; it is the direct result of the UFW firewall on the Linux VM doing its job by blocking the unauthorized connection.

***

### Conclusion

This test successfully demonstrates UFW's default security posture. The firewall correctly identified an incoming connection to an unallowed port and dropped it, proving that the system is properly secured. The connection failure is the expected and desired outcome.





## Testing a UFW "Deny" Rule

This document explains how an explicit `deny` rule in UFW blocks traffic, even for a commonly allowed service.

 ![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/main/Screenshot%202025-08-09%20141711.png)
![img alt](https://github.com/swamy-2006/SETUP-and-CONFIGURATION-of-the-FIREWALL/blob/main/WhatsApp%20Image%202025-08-09%20at%209.13.43%20PM.jpeg)

***

### The Firewall Configuration (Linux VM)

The terminal in the Linux virtual machine shows that a specific `deny` rule was manually added to the firewall:

```bash
sudo ufw deny 22/tcp
```
* This command instructs the Uncomplicated Firewall (UFW) to explicitly block all incoming connections on TCP port 22, which is the standard port for SSH. A deny rule like this will take precedence over any existing allow rules for the same port.

The Connection Test (Windows Host)
From the Windows host machine, a connection to the Linux VM was attempted on the newly blocked port:
```
telnet 10.0.2.15 22
```
* *The immediate result was a connection failure:*

Could not open connection to the host, on port 22: Connect failed

This message confirms that the firewall on the Linux VM is actively enforcing the deny rule and successfully dropped the connection attempt.

* Conclusion
This test is a success. It clearly demonstrates that creating an explicit deny rule in UFW is an effective way to block access to a specific port, and the firewall performs exactly as configured.


--------------------






















































 

##  Firewall Fundamentals

### 1. What is a firewall?
A firewall is a network security system that acts as a protective barrier between a trusted internal network (like your home or office network) and an untrusted external network (like the internet). It monitors and controls incoming and outgoing network traffic, deciding whether to **allow** or **block** specific traffic based on a predefined set of security rules. Think of it as a digital security guard for your network. 🛡️

---

### 2. Difference between stateful and stateless firewall?
The key difference lies in how they inspect traffic and track connections.

* **Stateless Firewall:** This type of firewall examines each data packet in isolation. It makes its allow/block decisions based only on the information in that single packet's header (like source/destination IP address and port). It has no memory of past packets. It's fast but less sophisticated.
* **Stateful Firewall:** This firewall is more intelligent. It not only inspects packet headers but also monitors the **state** of active connections (e.g., has a proper connection been established?). It maintains a "state table" of all active sessions. This allows it to know if incoming traffic is a legitimate response to an outgoing request or if it's unsolicited and potentially malicious. Stateful firewalls are more secure and are the standard in modern networking.

> **Analogy:** A **stateless** guard checks every person's ID every time they enter, even if they just left a second ago. A **stateful** guard remembers that you're an employee who just stepped out for coffee and lets you back in without a full security check, while still stopping unfamiliar faces.

---

### 3. What are inbound and outbound rules?
Firewall rules are categorized by the direction of the traffic they control.

* **Inbound Rules:** These apply to traffic **coming into** your network from the outside world. They control what external users and systems are allowed to access on your network.
    * **Example:** An inbound rule might `ALLOW` traffic on port 443 (HTTPS) so that people on the internet can visit your web server.
* **Outbound Rules:** These apply to traffic **going out from** your network to the internet. They control what external services your internal computers are allowed to connect to.
    * **Example:** An outbound rule might `BLOCK` traffic to known malicious IP addresses to prevent internal computers infected with malware from "phoning home" to an attacker.

---

### 4. How does UFW simplify firewall management?
**UFW**, or **Uncomplicated Firewall**, is a user-friendly interface for managing the powerful but complex `iptables` firewall built into the Linux kernel.

`iptables` requires long, intricate commands to configure rules. UFW simplifies this dramatically by providing a much more intuitive and readable command structure.

For example, to allow SSH traffic:
* **UFW command:**
    ```bash
    sudo ufw allow ssh
    ```
* **iptables equivalent:**
    ```bash
    sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    ```
By abstracting away the complexity, UFW makes it much easier and faster for system administrators to secure a server without needing to be an `iptables` expert.

---

### 5. Why block port 23 (Telnet)?
Blocking port 23 is a fundamental security best practice because the **Telnet protocol is insecure**.

The main reason is that Telnet transmits all data, including **usernames and passwords, in plain text**. This means anyone "listening" on the network can easily steal login credentials. It is highly vulnerable to eavesdropping (or "packet sniffing") attacks.

The modern, secure alternative is **SSH (Secure Shell)**, which runs on port 22 and encrypts the entire connection, protecting all data from being intercepted.

---

### 6. What are common firewall mistakes?
Some of the most frequent errors when configuring firewalls include:

* **Overly Permissive Rules:** Creating "allow any to any" rules that essentially negate the purpose of the firewall.
* **Forgetting Implicit Deny:** Most firewalls have a default policy to block any traffic not explicitly allowed. Forgetting this can lead to accidentally blocking critical services (like DNS).
* **Not Reviewing Logs:** Firewall logs are a goldmine of information about blocked attempts and potential threats. Failing to monitor them means you might miss the signs of an attack.
* **Rule Clutter:** Not removing old or unnecessary rules. This makes the firewall configuration hard to manage and can leave security holes from obsolete services.
* **Ignoring Outbound Traffic:** Only focusing on blocking inbound threats while allowing all outbound traffic. This can allow malware to exfiltrate data or connect to command-and-control servers.

---

### 7. How does a firewall improve network security?
A firewall is a cornerstone of network security for several reasons:

* **Access Control:** It enforces a strict policy on what traffic is allowed in or out of the network, preventing unauthorized access.
* **Threat Prevention:** It serves as the first line of defense, blocking many automated attacks and scans before they can ever reach a vulnerable application on your server.
* **Network Segmentation:** Firewalls can be used to divide a network into smaller, isolated zones. If one zone is compromised (e.g., the guest Wi-Fi), the firewall can prevent the attack from spreading to more critical areas (like the corporate servers).
* **Logging and Auditing:** It provides a detailed log of traffic, which is invaluable for identifying attack patterns and conducting forensic investigations after a security incident.

---

### 8. What is NAT in firewalls?
**NAT** stands for **Network Address Translation**. It's a technique used by firewalls and routers to allow multiple devices on a private network to share a single public IP address.

**How it works:**
1.  Your internal devices (laptops, phones) have **private** IP addresses (e.g., `192.168.1.5`), which cannot be used on the public internet.
2.  Your firewall/router has one **public** IP address from your Internet Service Provider.
3.  When your laptop sends a request to the internet, the firewall "translates" the source private IP (`192.168.1.5`) into its own public IP address and forwards the request.
4.  When the response comes back from the internet, the firewall remembers which internal device made the original request, translates the public IP address back to the correct private IP, and sends the data to your laptop.

The key **security benefit** of NAT is that it **hides the internal network structure** from the outside world. An attacker on the internet can only see the firewall's single public IP; they cannot see or directly target the individual devices behind it.

---
* *[**NOTE** : THE MOST OF THE CONTENT FROM THE AIs with MY OBSERVATION and THOUGHTS]*
