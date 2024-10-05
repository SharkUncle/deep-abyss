# Useful resources for everything:

This is a list of resources that can make the life easier.

## Arsenal

Useful for CTF, quick search a command for a specific tool and customise the option.

https://github.com/Orange-Cyberdefense/arsenal

## Awesome GPT Agents

The repo contain awesome agents for Cybersecurity for ChatGPT.

The list contains a lot of resources, all the topics are included. From the malware analysis to the legal, you will find what you need.

**Only for the Plus subscription**

https://github.com/fr0gger/Awesome-GPT-Agents

## Cheat.sh

Use it to quickly search answer without browsing many online forum.

Command:
```
# Installation
curl -s https://cht.sh/:cht.sh | sudo tee /usr/local/bin/cht.sh && sudo chmod +x /usr/local/bin/cht.sh

# Command
cht.sh <lang> <query>
cht.sh --shell <lang>
```

https://github.com/chubin/cheat.sh

https://cht.sh/

## DevSecOps Guides

A good resources for the DevSecOps field.

The guide is about good practices to integrating security into the software development life cycle.

https://devsecopsguides.com

The contents are good and detailed, all the parts are covered.

And they have a GPT, which is pretty good.

https://chatgpt.com/g/g-SAOYn4UCp-devsecops-guides

## Exegol

A very useful and powerful setup.

The official documentation is very simple to follow for the installation process.

https://github.com/ThePorgs/Exegol

https://exegol.readthedocs.io/en/latest/

## gitlab-ci-local

A friend of mine show me this incredible tool.

If you work on a Gitlab CI/CD pipeline and you need to test a specific step, you can install this tool. It can run on your system a Gitlab pipeline more light and more quick. It save a lot of time. And it is easy to use.

https://github.com/firecow/gitlab-ci-local?tab=readme-ov-file#installation

## HTML Preview

GitHub & BitBucket HTML Preview is a great resource, it permit to use html code and to render the file. Plus you don't need to clone or download it to use it.

Just add: `https://htmlpreview.github.io/?` to any URL of HTML file.

https://github.com/htmlpreview/htmlpreview.github.com?tab=readme-ov-file

## Metasploit Unleashed

The Free Online Course and probably the best for learning Metasploit Framework alias MSF.

It present all the content of Metasploit, this framework is owned by Rapid7.

Metasploit is a great resource, it help with security audits, penetration tests, enumeration, offensive and defensive, and many things.

https://www.offsec.com/metasploit-unleashed/

## osint4all

A great resource for OSINT. With a lot of links.

https://start.me/p/L1rEYQ/osint4all

## OWASP Juice Shop

A well known insecure web application. This is an awesome resource to learn web vulnerabilities.

Just it is describe on the OWASP web page: "It can be used in security trainings, awareness demos, CTFs and as a guinea pig for security tools!"

Give it a try and some time, because there is a lot of things to do on this one.

https://owasp.org/www-project-juice-shop/

https://juice-shop.herokuapp.com/#/

https://github.com/juice-shop/juice-shop

## Proton

Proton is great for the email and the VPN.

You can subscribe for free and use a secure mailbox and a VPN. I'm not sponsored by the enterprise so you don't have to follow my advice. It's entirely personal.

https://proton.me/mail

https://protonvpn.com

You can configure OpenVPN for Proton VPN in Linux, this is easy and the result save time.

https://protonvpn.com/support/linux-openvpn/

https://protonvpn.com/support/openvpn-windows-setup/

## Trace Labs OSINT VM

A friend of mine speak to me about this resource and I want to test it and see what it can do.

This is a virtual machine available by the Trace Labs team. Their describe themself just like taht in the web site: "Trace Labs is a nonprofit organization whose mission is to accelerate the family reunification of missing persons while training members in the trade craft of open source intelligence (OSINT)".

The goal is to help people and researcher with an up-to-date VM that include tools for OSINT.

In order to test it, click on the "Download OVA" in the main web page. Once donwload, you just need to import the OVA file and start the machine.

*The password is very simple osint:osint*, it is a good practice to change the default password. Feel free to do whatever you want I'm not your CISO.

Once you are connect with the super robust credential on your kali, you can see some resources on the desktop. I think this one can be a realy good link to give a try:

https://github.com/tracelabs/tofm/blob/main/tofm.md

At the frst connection the VM work well, the background is cool but there a little prbolem. There are zero tools installed on it. When you check the destop earlier, there is one interesting icon: 'install-tools.sh'.

The file name is rather explicit, verify that it can be executed with `ll install-tool.sh`.

Do a `sudo apt update` to check for updates on your kali linux distro. Just in case, because the distro doesn't have any tool so in therory zero update to do.

Run the install script: `./install-tool.sh` now grab a coffee or do the dishes.

After that you have OSINT tools installed. I searched for some well known tool and they were install.

When you start Firefox browser you have already a list of bookmarks for OSINT research inluded in you bookmarks toolbar.

https://www.tracelabs.org/initiatives/osint-vm
