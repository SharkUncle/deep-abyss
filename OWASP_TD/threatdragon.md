# Threat Modeling with OWASP Threat Dragon

OWASP Threat Dragon is a free, open-source, cross-platform threat modeling application.

https://owasp.org/www-project-threat-dragon/

Github repository: https://github.com/OWASP/threat-dragon

[Threat modeling](https://csrc.nist.gov/glossary/term/threat_modeling) is a form of risk assessment that models aspects of the attack and defense sides of a logical entity, such as a piece of data, an application, a host, a system, or an environment.

It's a part of risk assessment

Documentation: https://owasp.org/www-project-threat-dragon/docs-2/

Demo live: https://www.threatdragon.com/#/

The tool can be install with three options:
1) Local desktop: download the .rpm or the Appimage
2) Web app: clone the Git repository and use rpm to install it
3) Docker: pull the container from the Docker and run it

I choose the Docker container, I try to force myself to use Docker the most I can.

If you need to have more information visit the OWASP cheat sheet for [Threat modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

### STRIDE approach for Threat modeling

Before go deeper in the tool, there is a methodology to identify and asses threats on a system.

STRIDE goes for:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation disclosure
- **D**enial of service
- **E**levation of privilege

This methodology for analyzing threats is particularly interesting when you want to study the risk of your suppliers. Supply chain attack and environment around system are much more complex, threat modeling can help to analyze the security of the subcontractors and to identify the dependencies.

*There's a lot of resources available online if you want to learn more about STRIDE-based approach*

## Installation

The Docker Hub page contain the pull command needed: `docker pull owasp/threat-dragon`

The 'Tags' tab detail the version and the command to pull a specific version or the most stable one: `docker pull owasp/threat-dragon:stable`

Sometimes a specific configuration can be required with the environment you work on. This is the case here for this tool.

## Setting up the environment

The tool is not ready to be tested already. Before using OWASP Threat Dragon it need to have the environment set.

I won't use the external dependencies normally (just for a test I don't think so), in order to do that you will need to install Dotenv. This tool help to create environment variables for the project.

https://github.com/motdotla/dotenv#readme

https://github.com/dotenvx/dotenvx

OWASP Threat Dragon need to have a `.env` file to work. Even for the Docker version. Environment variables need to be set first before running the Docker container.

In order to do that, create the file needed in the directory of your project: `vim .env`

The `example.env` file can be check here: https://github.com/OWASP/threat-dragon/blob/main/example.env

This file from the official repository contain all the variable possibles for the tool. Just get the one needed for the environment.

Content of the `.env` file for the test:
```
ENCRYPTION_KEYS='[{"isPrimary": true, "id": 0, "value": "11223344556677889900aabbccddeeff"}]'
ENCRYPTION_JWT_SIGNING_KEY=asdfasdfasdf
ENCRYPTION_JWT_REFRESH_SIGNING_KEY=fljasdlfkjadf
NODE_ENV=development
SERVER_API_PROTOCOL=http
```

*This is the default file for the environment variable*

There are a lot of possible use case for this tool, this is a awesome that you can adjust the tool to your need. Especially when the environment is restricted, and you have the dependencies manage locally (repository, Git, etc.).

The docker command to run Threat Dragon:
`docker run -it --rm -p 8080:3000 -v $(pwd)/.env:/app/.env owasp/threat-dragon:stable`

This command will run the threat dragon container on the 8080 port of your localhost, and create a share between your system host and the container.

After that use the browser to access the web page: `http://localhost:8080/`

## Other functionalities

### Import an existing threat model

On the main page, the option 'Import' is possible. Add the existing model in the 'JSON' format.

### Demo sample

The main page provide example, select between the different sample and see the threat model available.

## Threat model creation

The more interesting use case for OWASP Threat Dragon is to create a new threat model. Provide the information needed for the new model.

*It is possible to add a model, for my test I choose the STRIDE format.*

My threat model is a supply chain attack in an industrial environment. When the information need for the model are complete, click on the 'Save button'.

It will save the model in a 'JSON' format.

Next, to work on the project click on the name of the model . It will open the mode creation page. On the left panel it is 

This resource help to create the diagram threat model: https://owasp.org/www-project-threat-dragon/docs-2/diagrams/