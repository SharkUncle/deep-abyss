# CISO Assistant

**IN PROGRESS**

Notes for testing CISO Assistant locally.

CISO Assistant is an open-source tool for GRC. It can be used for risk management and to help CISO. Yes nobody's perfect. If it is possible to make GRC less painful, it worth the try.

Link to the repository on Github: https://github.com/intuitem/ciso-assistant-community

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

### Start CISO Assistant after you shut down your computer

You start again all the container with the following command, in the directory where the repo is clone:
`docker compose up -d`

## How to use CISO Assistant

The Official documentation is well written for the first steps, and the tool is pretty straightforward. So nothing complicate. If you already used a risk assessment tool, you won't be lost.

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

### Threats and Mitigations

For my test I go to "Extra" > "Libraries", and I'm surprised by the number of the resources available. Yes I know, I don't need much to be amazed. **BUT**, this is it. When you have to prepare for your customer the legal framework or controls, you always have to go online and search on "Google" or ask "ChatGPT" to :
- What are the controls applicable?
- What is the regulation for this business sector?
- How can I retrieve all the controls the MIST have published?

Well, this section save a lot of time and some headache.

You can search for example: "Mitre ATT&CK v14 - Threats and mitigations"

Just click on the icons to download the library and it's automatically add to you assistant. You can consult it by clicking on the library and read ALL the framework, because you can do it with CISO Assistant.

*The Mitre ATT&CK v14 - Threats and mitigations framework reveals itself useful, it automatically fills the "Threats" and "Reference controls" under the "CONTEXT" section.*



----------------------------------------------------------------------------------------------------

### Pros/cons

This is my vision of the tool, don't take it for the absolute truth.

I encourage you to test it, so you can have your own opinion.

| Pros                                                   | Cons                                    |
| ------------------------------------------------------ | --------------------------------------- |
| There a lot of security guide in the libraries section | The official documentation is light     |
| Easy to install                                        | It is easy to get lost in the interface |
| Easy to follow the risks stored                        | It's not a risk assessments tool        |
