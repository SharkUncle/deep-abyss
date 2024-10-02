# OWASP Dependency Check test

**IN PROGRESS**

OWASP Dependency Check (ODC) is tool provide by the OWASP foundation help identify publicly disclosed vulnerabilities within project dependencies. It scans the libraries or components a project depends on and checks whether any of them have known vulnerabilities.

https://github.com/jeremylong/DependencyCheck

This test cover the basic use cases for this tool. I'm not an expert in DevOps and in Cybersecurity, you can check online for a better guide if this one is not sufficient.

This tool is used for Software Component Analysis (SCA), it can be included in a pipeline CI/CD. In Github action, Gitlab CI or Jenkins. I will not cover all of this parts, so feel free to make your own research.

BTW the tool generate complete and detailed reports. ODC is have a lot of options, you can check the official documentation to have a look:

https://jeremylong.github.io/DependencyCheck/

DevSecOps is interesting in the security field, there's a lot of resources available online.

## Installation

The installation of the tool is pretty simple.

https://jeremylong.github.io/DependencyCheck/dependency-check-cli/index.html

This is well describe on the web page, so follow the instructions.

Download on the GitHub page of the project the release:
- [dependency-check-version-release.zip](https://github.com/jeremylong/DependencyCheck/releases)
- [dependency-check-version-release.zip.asc](https://github.com/jeremylong/DependencyCheck/releases)

Then import the GPG key used to sign all releases, with the command given:

`gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 259A55407DD6C00299E6607EFFDE55BE73A2D1ED`

On the same directory where you place the .zip archive and the .zip.asc file, use the following command to verify the integrity:

`gpg --verify dependency-check-10.0.4-release.zip.asc`

When it is done and all the step correctly perform, the output of the command shall return:
`gpg: Good signature from "Jeremy Long <jeremy.long@gmail.com>"`

It is a good practice to always check the integrity of the software you download online. You never know maybe one day it will save your life.

Now unzip the archive: `unzip dependency-check-10.0.4-release.zip`

Go to the dependency-check directory: `cd dependency-check`

To finish the installation, check if all is good:
```
cd bin/
./dependency-check.sh --help
```

The help message is shown on the terminal, this is good. Now the installation process is finished.

**FYI**: a container is available and can be pull from the Docker hub. It is very useful if you work on a CI/CD pipeline.

https://hub.docker.com/r/owasp/dependency-check

*Maybe I will cover this part later*

## Configuration

The configuration of the OWASP Dependency Check tool is very simple.

But there is something mandatory before continuing? OWASP Dependency Check need to have a database to function properly, it use an H2 database to perform the test. But in order to work, the first thing is to update the tool with the latest vulnerabilities database.

### Update the CVE database

For updating it you will need an API key to the NVD data-feed. You can obtain a key directly on the NVD web site:
https://nvd.nist.gov/developers/request-an-api-key

You need to give some informations, don't worry it just asking:
- Organization Name
- Email Address
- Organization Type

And click on "I agree to the Terms of Use"

After that you will receive your API key in you Inbox email.

Keep it somewhere relatively secure where you won't lost it.

Now, you can update your database with the latest vulnerabilities register in the NVD CVE database.

For updating the database, use the following command: `./dependency-check.sh --updateonly --nvdApiKey <your API key>`

Get a coffee it will take a little depending on you connection to update the database.*

Now you will see a new directory in the dependency-check directory "data". It contain the database, the "CISA Known Exploited Vulnerability" and other thing that you can see.

## ODC arguments

https://jeremylong.github.io/DependencyCheck/dependency-check-cli/arguments.html

The documentation show a list of arguments separate in two part:
- The command line arguments: useful for the operation needed
- Advanced options: all the options available for the commands

The very basic use of this tool it to start a scan against a project you have. It will scan all the file and the archive to find vulnerabilities on the dependencies of your code.

The format of the output can be choose between different type of file.

The basic command is this one:

`./bin/dependency-check.sh --enableExperimental --project "<your project>" --scan /path/to/scan -f "ALL"`

`--enableExperimental`: This argument is very useful it permit to scan a lot more files. But it generate a lot of false positives and false negatives. Activate this argument only if you need to scan a file not cover by the base configuration.

When the scan is finished, check your directory with `ls` or whatever command you use.

You will see a lot of reports in different format. This is the results of your scan.

The most visual is the html, bit personally I prefer the json it is much more useful when you need to script the outputs.

I will not cover all the command here, just specific use case I think useful. Feel free to explore the tool, it's much more complex than it looks.

I put the report in HTML format, just check the result and see by yourself.

[Basic report](https://htmlpreview.github.io/?https://github.com/SharkUncle/deep-abyss/blob/master/OWASP_DC/basic-dependency-check-report.html)

The report is the results of the scan of the DVJA directory, I'll go into more detail in the next section.

## Scan more files than just the basic

Sometimes the basic command will not scan all the files to find all the dependencies.

### pom.xml

For this type of file maven need to be configured.

https://maven.apache.org/

**Maven** is a build automation tool used primarily for Java projects, not necessarily just Java but also C#, Ruby, etc.

It is very useful when you need to build a project and to check the dependencies. That's why we're here.

Maven installation is easy, use the package manager (for Linux user with apt, Google is your friend for this): `sudo apt install -y maven`

Now, it is time to use maven to run OWASP Dependency Check on a Java project.

I choose the [Damn Java Vulnerable Application](https://github.com/appsecco/dvja) for this test.

Clone the Git repository to your system: `git clone https://github.com/appsecco/dvja`

Now go to the dvja/ directory and next use maven to check DVJA project for dependencies vulnerability:
```
cd dvja/
sudo mvn org.owasp:dependency-check-maven:check -Dformat=HTML -DoutputDirectory=./rapports
```

The scan take 2 at 3 minutes, on my computer of course. Go take a coffee and check the awesome reports after that.

At the end of the scan, check the target/ directory for the report in the HTML format.

I choose the HTML format for this example, but you can choose another format.

I put my [reports](https://htmlpreview.github.io/?https://github.com/SharkUncle/deep-abyss/blob/master/OWASP_DC/detailed-dependency-check-report.html), you can see by yourself the results and compare it. Or just check this one if you don't have time.

Now the report is not good at all, it contain 26 vulnerable dependencies and 185 vulnerabilities. The jobs end here for this tool, but the Consultant need to filter the false positives before preparing the final report.

You can see the Log4j vulnerability contain in the DVJA repository.

The good part using ODC like that is you don't need to update the NVD database. But it can be used in all environment. Sometimes you are in an offline environment and it can be a headache.

### CMake file case

ODC can scan CMake file, but this scan is use with the *Experimental* argument:

`--enableExperimental`

File scan: `CMakeLists.txt, *.cmake`

Check the command use for the basic case of ODC, this test can be customized if needed.
