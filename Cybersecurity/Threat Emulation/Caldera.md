It is suggested to clear the following rooms first before proceeding with this room:

- [Introduction to Threat Emulation](https://tryhackme.com/room/threatemulationintro)
- [Atomic Red Team](https://tryhackme.com/room/atomicredteam)
- [Windows Event Logs](https://tryhackme.com/room/windowseventlogs)
- [Aurora](https://tryhackme.com/room/auroraedr)

# What is CALDERA?

![CALDERA logo.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/fbff8be5efc5ffd6ff3f2c9b046ed2bb.png)[CALDERA™](https://github.com/mitre/caldera) is an open-source framework designed to run autonomous adversary emulation exercises efficiently. It enables users to emulate real-world attack scenarios and assess the effectiveness of their security defences.

In addition, it provides a modular environment for red team engagements, supporting red team operators for the manual execution of TTPs and blue teamers for automated incident response actions.

Lastly, CALDERA is built on the [MITRE ATT&CK framework](https://attack.mitre.org/) and is an active research project at MITRE. All the credit goes to MITRE for creating this fantastic framework.

Use Cases of CALDERA

Security analysts can leverage the CALDERA framework in different cases, but the common usages of CALDERA are as follows:

- **Autonomous Red Team Engagements:** The original CALDERA use case. The framework is built to emulate known adversary profiles to see gaps across your organisation's infrastructure. This use case allows you to test your defences and train your team on detecting threats.
- **Manual Red Team Engagements**: Aside from automating adversary profiles, CALDERA can be customised based on your red team engagement needs. It allows you to replace or extend the attack capabilities in case a custom set of TTPs are needed to be executed.
- **Autonomous Incident Response:** As mentioned, blue teamers can also use CALDERA to perform automated incident response actions through deployed agents. This functionality aids in identifying TTPs that other security tools may not detect or prevent.

Breaking Down CALDERA

Before playing with the CALDERA interface, let's dive deep into the core terminologies. The information in this section is required to understand the framework better and tailor it based on your engagement needs. Let's have a quick run-through of the critical items to be introduced in this task.

1. **Agents** are programs continuously connecting to the CALDERA server to pull and execute instructions.
2. **Abilities** are TTP implementations, which the agents execute.
3. **Adversaries** are groups of abilities that are attributed to a known threat group.
4. **Operations** run abilities on agent groups.
5. **Plugins** provide additional functionality over the core usage of the framework.

These topics will be detailed as we go through the task content.

﻿**Agents**  

Given the name, agents are programs continuously connecting to the CALDERA server to pull and execute instructions. These agents communicate with the CALDERA server via a contact method initially defined during agent installation.

CALDERA has several built-in agent programs, each showcasing a unique functionality. Below are some examples of it:

|   |   |
|---|---|
|**Agent Name**|**Description**|
|Sandcat|A GoLang agent that can establish connections through various channels, such as HTTP, GitHub GIST, or DNS tunnelling.|
|Manx|A GoLang agent that connects via the TCP contact and functions as a reverse shell.|
|Ragdoll|A Python agent that communicates via the HTML contact.|

Agents can be placed into a **group** at install through command line flags or editing the agent in the UI. These groups are used when running an operation to determine which agents to execute abilities on.

In addition, groups determine whether an agent is a red or a blue agent. Any agent that belongs to the blue group will be accessible from the blue dashboard, while all other agents will be accessible from the red dashboard.

**Abilities and Adversaries**

An ability is a specific MITRE ATT&CK technique implementation which can be executed through the agents. These abilities include the following information:

- Commands to be executed
- Compatible platforms and executors (e.g. PowerShell, Windows Command Shell, Bash)
- Payloads to include
- Reference to a module

Adversary profiles are groups of abilities showcasing the TTPs attributed to a threat actor. Selecting an adversary profile determines which abilities will be executed by the agent during an operation. 

An example image below lists the abilities under Alice 2.0 adversary profile. Each ability is attributed to a MITRE ATT&CK Tactic and the corresponding techniques to be executed.

![Alice 2.0 Adversary Profile.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/8184f6e22e058dbed6456294e053a511.png)  

_**Adversary Profile: TTPs of Alice 2.0**_

**Operations**

As the name suggests, operations run abilities on agent groups. The adversary profiles define which set of abilities will be executed, and agent groups determine which agents these abilities will be performed.

During the execution, the planner can determine the order of abilities. A few examples of these are detailed below:

- Atomic - Abilities are executed based on the atomic ordering (Atomic of Atomic Red Team).
- Batch -  Abilities are executed all at once.
- Buckets - Abilities are grouped and executed by its ATT&CK tactic.

Given these options, the planner feature allows users to control and give variations to the execution order of abilities during operations.

Aside from the given terminologies above, you also need to understand the following concepts to configure an operation:

- **Fact** - An identifiable information about the target machine. Facts are required by some abilities to execute properly; hence they should be provided through fact sources or acquired by a previous ability.
- **Obfuscators** - Sets the obfuscation of each command before being executed by the agent. 
- **Jitter** - The frequency of the agents checking in with the CALDERA server.

**Plugins**

Since CALDERA is an open-source framework, it is extended by different plugins that provide additional functionality over the core usage of the framework. By default, CALDERA contains several plugins at users' disposal during adversary emulation exercises. A few notable examples are the following:

- **Sandcat** - One of the agents available in CALDERA. This agent can be extended and customised through this functionality.
- **Training** - A gamified certification course to learn CALDERA. 
- **Response** - Autonomous Incident Response Plugin (will be discussed further in the later tasks)
- **Human** - Allows users to simulate "human" activity, which may provide a benign and realistic environment.

To learn more about the plugins, you may refer to this [link](https://caldera.readthedocs.io/en/latest/Plugin-library.html).

