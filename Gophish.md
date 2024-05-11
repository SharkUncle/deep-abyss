# Gophish Local Test

## Needs:
First install docker on a Kali linux distro.
https://www.kali.org/docs/containers/installing-docker-on-kali/

The second part for docker-ce is used.

Docker hub image for gophish:
https://hub.docker.com/r/gophish/gophish

Start the containor with the following command:
`docker run -it --rm --network host <container image ID>`

## Installation:

Install postfix locally:
https://gist.github.com/raelgc/6031274

Install thunderbird on the kali distro.
*kali doesn't have the firefox repository activate*
https://support.mozilla.org/en-US/kb/installing-thunderbird-linux#w_installing-from-your-distribution-package-manager
https://www.thunderbird.net/en-US/thunderbird/all/

Thunderbird is well bugged, Betterbird seam promising.
*The installation process is not simple on debian based distro*
https://www.betterbird.eu/
### Postfix:

Local email server.
https://gist.github.com/raelgc/6031274

## Gophish

The environment is now configure, let's start a fake campaign on Gophish.

Change the password, on the admin panel.

Go to the 'Sending Profiles' and changes the parameter to match the postfix configuration.

![Sending_profile]("/home/uncle/Documents/Obsidian Vault/Pasted image 20240510232638.png")

Now send the test mail:
![Chek]("/home/uncle/Documents/Obsidian Vault/Pasted image 20240510232702.png")

Now start configuring the campaign.

#### Landing page

#### Email templates


##### Troubleshoot

Add apt-apt-repository, with apt.
- Correct the python error: https://askubuntu.com/questions/1480616/adding-opencpn-repository-attributeerror-nonetype-object-has-no-attribute
