# CISO Assistant

Notes for testing CISO Assistant locally.

Link to the repository on Github: https://github.com/intuitem/ciso-assistant-community
[gophish](https://github.com/SharkUncle/deep-abyss/blob/master/Gophish.md)

My first idea of the tool was "Cool, another note manager!", well I've never been so happy to be wrong.

It offer very interesting about 
## Installation

For the test on my local system, it is very simple. You need to install first docker on target system.

You can install it, like I did, on your host.

For the installation you can follow the official documentation:
- Clone the repo: `git clone https://github.com/intuitem/ciso-assistant-community.git`
- Go to: `cd ciso-assistant-community`
- Now if you dont have Docker compose you can install it for all users like this:
	- For Debian: `sudo apt-get install docker-compose-plugin`
	- Or Manually:
		- Create the directory, like this all users can use Compose: `sudo mkdir -p /usr/local/lib/docker/cli-plugins`
		- Download the Compose CLI plugin: 
			- Check the last version on: https://github.com/docker/compose/releases
			- `curl -SL https://github.com/docker/compose/releases/download/v<VERSION>/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose`
		- `sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose`
		- Last test the installation: `docker compose version`
- Now you run the Docker Compose install: `./docker-compose.sh`
- After it, you can browse the web page: https://localhost:8443/
- After the first connection, you need to change your password, choose one you can remember or use a manager (whatever you want).

## How to use CISO Assistant

The Official documentation is well written, and the tool is pretty straightforward. So nothing complicate. If you already used a risk assessment tool, you won't be lost.

First you need to create a domain:
- Navigate with the left panel to 'ORGANIZATION' > 'Domains'
- Click on 'Add domain' and create one for the local test.

Next create a Project:
- Click on "Add project"
	- Specify a "Name"
	- The description is optional
	- Add the Domain you have already create
	- The "Internal reference" is optional, it may be helpful if you have multiple projects in progress
- You can click on "Save"

This is the two first basic step to create an environment.

I will go a little further. The project and the domain are the very basic, but it's incomplete for me. Rapidly all audits and risk assessments need assets. You know the famous **Business assets** and the **Support assets**. You can't make GRC activities without at least identify them.

A quick reminder about the primary and support [asset in the ISO/IEC 27002 3.1.2](https://www.iso.org/obp/ui/en/#iso:std:iso-iec:27002:ed-3:v2:en):
- Primary:
	- Information
	- Business process
- Supporting:
	- Hardware
	- Software
	- Network
	- Personnel
	- Site
	- Organization's structure

On the left panel go to **CONTEXT > Assets** and "Add asset".

When you edit your asset, you need to specify the "Type": 'Primary' or 'Support'.

Then it is time to add 'Threats' and 'Mitigation' measures for them.

### Threats and Mitigations

For my test I go to "Extra" > "Libraries", and I'm surprised by the number of the resources available. Yes I know, I don't need much to be amazed. **BUT**, this is it. When you have to prepare for your customer the legal framework or controls, you always have to go online and search on "Google" or ask "ChatGPT" to :
- What are the controls applicable?
- What is the regulation for this business sector?
- How can I retrieve all the controls the MIST have published?

Well, this section save a lot of time and some headache.

You can search for example: "Mitre ATT&CK v14 - Threats and mitigation"

Just click on the icons to download the library and it's automatically add to you assistant. You can consult it by clicking on the library and read ALL the framework, because you can do it with CISO Assistant.

*The Mitre ATT&CK v14 - Threats and mitigation framework reveals itself useful, it automatically fills the "Threats" and "Reference controls" under the "CONTEXT" section.*

CISO Assistant offer the possibility to add controls and threats, and don't use the library. Like this it's possible to customize all the aspects of the risk assessments or the security audits.

## Risk assessment

When you browse the web site of [CISO Assistant](https://intuitem.com/ciso-assistant/) it introduces the tool like a Risk Assessment. In my opinion it's partially true, if you have a customer with a specific need like: an accreditation file, a security audit who an audit that imposes a risk assessments method, this tool will partially help you in this task. But for the day-to-day risk follow-up it will be perfect.

In order to use the risk assessments capacity, you have to first specify the context:
- The **asset** you want to analyze
- The **threat** you want to evaluate
- The **current** and the **residual** risk
- The **controls** to applied

Then you go to **Risk assessments** And create the first risk assessment using the '+ Add risk assessment' button.

After that click on the new assessment, a new page appeared. On this page you have the resume of your Risk Assessment (RA), the **Associated risk scenarios** and the matrix view.

Click on the '+ Add risk scenario' button, and specify the name you want and the threat from the MITRE or the one you want. You can specify a threat in the **CONTEXT > Threats** menu on the left panel.

When the risk scenario is create, it can be accessed by clicking on it. Now the 'Edit' button on the top left of the page permit to specify:
- The scope
- The status
- The threats
- The assets
- The current risk
- The residual risk
- The knowledge needed

It is pretty detailed, when you return on your RA the matrix has been updated with the new risk level.

In the 'COMPLIANCE' part of the menu the 'Evidences' can be specify. This is useful for the 'Audits' part, but you can use it in the RA too. The evidence can be associate to the assessment for the control part.

On the same page you have a 'Remediation plan' button, the control applied in the risk scenario are show in this page with the status and the ETA associate.

The last menu on the left panel is the 'Risk acceptances', add with the button '+ Add risk acceptance' a risk. This part is very interesting, because all risk need a remediation measure. But someone need to validate the correct remediation, ideally the 'Approver' need to be someone different than the one implement it.

It need to be noted that the RA can be export in PDF or CSV format on its page.

## Audits

The job of the CISO is not limited to the security part but also to the compliance. Whatever the business the company is running, a regulation is applicable. For the personal data, health, payment, classified, or specific activity the CISO needs to know its level of compliance.

In order to know it the method it's to audit the organization, and hope that the level is good.

Go to **COMPLIANCE > Audits** and click on '+ New Audit'; Here specify the informations needed, you can also:
- Select a 'Framework' you have previously added
	- The 'International standard ISO/IEC 27001:2022' is a good one for start
- The authors and the reviewers need to be a different person of course

Next, when it's create you select the audit and see a new page with the status of the audits and the requirements analyzed.

Like always for the compliance audit you choose you need to access all the controls, analyze if it applicable or not.

Then, create or add the control associate. Evaluate the status and enable or not the scoring. Add the evidence to the control.

The most important part in the control page is the **Observation** part, it is a very good practice to always add an observation to the control.

When all the many controls are done, the audits page automatically update the 'Compliance' and the 'Progress' diagram. Like the RA you can access the 'Action plan' and export the results in ZIP or PDF format.

### Pros/cons

It's the perfect tool to replace the time-consuming excel file. Like always discuss with the customer about the use of this tool. Secure the computer for local use or the server if it use remotely.

The SSO integration can be very useful for the user management.

Like always the Excel is unfortunately largely adopted. But it is good to have hope when an organisation put this kind of tool Open-Source.

| Pros                                                   | Cons                                               |
| ------------------------------------------------------ | -------------------------------------------------- |
| There a lot of security guide in the libraries section | The official documentation is light                |
| Easy to install                                        | It is easy to get lost in the interface            |
| Easy to follow the risks stored                        | It's not a risk assessments tool for specific need |
| Evidence of risk management                            | Useful for a small perimeter                       |
| Save a lot of time                                     |                                                    |
| Bye Excel file                                         |                                                    |
