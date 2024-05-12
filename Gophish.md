# Gophish Local Test

This a steps by steps guide for testing Gophish in a local environment.

**For study only!**

## Requirements:

First install docker on a Kali linux distro.
https://www.kali.org/docs/containers/installing-docker-on-kali/

Docker hub image for gophish:
https://hub.docker.com/r/gophish/gophish

Start the container with the following command:
`docker run -it --rm --network host <container image ID>`

Why docker, because it is much more flexible and easy to use. I force myself to use it every time I can, so fell free to follow it or use another way.

## Installation of SMTP & Betterbird:

Install postfix locally:
https://gist.github.com/raelgc/6031274

Thunderbird doesn't support Movemail, Betterbird is well better for this test.
*The installation process is not simple on debian based distro*
https://www.betterbird.eu/

Download the tar archive and extract it. cd on the betterbird directory and start the mail client with: `./betterbird`

## Gophish

The environment is now configure, let's start a fake campaign on Gophish.

Change the password, on the admin panel.

Go to the 'Sending Profiles' and changes the parameter to match the postfix configuration.

Now start configuring the campaign.

**Reminder: the more realistic the campaign, the better the results will be.**

### Landing page

This is the web page view by the user once he click on the malicious link. It is write in HTML.

Go to this website or search on your favorite search engine a login page.
Or ask your assistant to generate HTML page with a form.

https://www.w3schools.com/howto/tryit.asp?filename=tryhow_css_login_form

*Don't take login page with online dependencies, prefer to take a page with all the code needed inside it.*

https://medium.com/@shopinson/how-to-create-a-login-form-w3schools-vs-bootstrap-6e8877f793af

### Email templates

Search again for an email template or just copy an email from your personnal inbox.

https://github.com/criggs626/PhishingTemplates/blob/master/emails/Upgrade%20Webmail.html

Add the HTML code in the new email template, and save it.

There is some variables available in Gophish, for the template and the landing pages.
Here some that can be useful:
- `{{.FirstName}}` :  first name of the user;
- `{{.URL}}` :  the URL use in the campaign;
- `{{.Email}}` :  the actual email used.

### Campaign

Create a campaign with clicking on the Campaigns > New Campaign. Then complete the information:
- Add a Name;
- Select the email template;
- Select the Landing Page;
- Specify the URL;
- Select the Sending Profiles;
- Set the Groups for the user to test.

Next, click on Launch Campaign.

Return to the betterbird application and click on "Get Messages".
Select the email you want to test, click on the link and provide the email user and a fake password.

Go to the dashboard on Gophish, select the campaign in progress and retreive all the results.

## Next step test with self signed certificate:

First create a self signed certificate with openssl:
`sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout gophish.key -out gophish.crt`

*Take care of the right on the files created and the user in the docker container.*

The cert and key file need to be moved in the Gophish directory with the config.json.

Modify the config.json in order to create an HTTPS campaign.

The template is on the Gophish git: https://github.com/gophish/gophish/blob/master/config.json

The phish_server need to be modify as following:
```
	"phish_server": {
		"listen_url": "0.0.0.0:443",
		"use_tls": true,
		"cert_path": "gophish.crt",
		"key_path": "gophish.key"
	},
```

I'm using the Docker version of Gophish, so I need to specify the config.json when I run docker.
Change command use before to: `docker run -it --rm -v ~/Gophish/config.json:/opt/gophish/config.json --network host gophish/gophish`

Then use docker cp to copy the self signed certificate in the gophish directory:
```
docker cp gophish.crt <gophish_container>:/opt/gophish
docker cp gophish.key <gophish_container>:/opt/gophish

docker exec -it <gophish_cantainer> sh # Use this to verify the files and permissions
```

Now everything is in place to get back on the Gophish panel and configure the new campaign using the certificate.
Specify the URL before launching it to: `https://127.0.0.1`

Go further:
https://www.n00py.io/2017/09/phishing-with-gophish-and-letsencrypt/

##### Troubleshoot

Add apt-repository, with apt.
- Correct the python error: https://askubuntu.com/questions/1480616/adding-opencpn-repository-attributeerror-nonetype-object-has-no-attribute
