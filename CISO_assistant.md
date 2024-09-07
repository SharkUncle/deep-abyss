# CISO Assistant

**IN PROGRESS**

Notes for testing CISO Assistant locally.

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

## How to use CISO Assistant

The Official documentation is well written, and the tool is pretty straightforward. So nothing complicate. If you already used a risk assessment tool, you won't be lost.

First you need to create a domain:
- Navigate with the left panel to 'ORGANIZATION' > 'Domains'
- Click on 'Add domain' and create one for the local test.

Next create a Project:





### Pros/cons


| Pros                                                   | Cons                                    |
| ------------------------------------------------------ | --------------------------------------- |
| There a lot of security guide in the libraries section | The official documentation is light     |
| Easy to install                                        | It is easy to get lost in the interface |
