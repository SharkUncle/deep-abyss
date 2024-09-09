# Gophish Local Test

This a step by step guide for testing Gophish in a local environment.

**For study only!**

## Requirements:

First install docker on a Kali linux distro.
https://www.kali.org/docs/containers/installing-docker-on-kali/

The second part: docker-ce is used.

I assume you have install Docker on your Kali Linux distro. If not you can go to the official documentation and follow the instructions.
https://www.kali.org/docs/containers/installing-docker-on-kali/

Docker hub image for gophish:
https://hub.docker.com/r/gophish/gophish

This is not a tuto on Docker, there a lot to cover and a lot of content online. So don't hesitate to use an alias for this or something you are more comfortable. Docker and container are very powerful, don't hesitate to give it a try.

Why docker, because it is much more flexible and easy to use. I force myself to use it every time I can, so fell free to follow it or use another way. It is also possible to install locally like it is describe in the Github repository.

### Install postfix locally

There is a few step to follow before using Gophish locally. The first one is installed and configured properly an SMTP Email server on Linux.

#### Modify the /etc/hosts file and add :

```
127.0.0.1       localhost
127.0.0.1       localhost.com
```

Use this command to modify the hosts file: `sudo nano /etc/hosts`

This will be use later for the domain email: `@localhost`

#### Install Postfix:

Install Postfix on Kali linux with apt: `sudo apt-get install postfix`

#### Configure Postfix to Local only:

- During postfix install process, the configure text dialog will display five options:

```
   General type of mail configuration: 
   
   No configuration
   Internet Site
   Internet with smarthost
   Satellite system
   Local only
```

- Select "Local Only".

- For the domain name, use the default suggested and finish the install.

#### Configure a Catch-all Address

After enabling this, it is possible to use any email address ending with: "@localhost" or "@localhost.com".

- If not exists, create file /etc/postfix/virtual: `sudo nano /etc/postfix/virtual`
- Add the following 2 lines content, replacing `<your-user>` with your **Unix** user account:

```
@localhost <your-user>
@localhost.com <your-user>
```

- Save and close the file.
- Configure postifx to read this file:
	- Open /etc/postfix/main.cf: `sudo nano /etc/postfix/main.cf`
	- And check if this line is enabled, or add it if not exists: `virtual_alias_maps = hash:/etc/postfix/virtual`
- Activate it: `sudo postmap /etc/postfix/virtual`
- Reload postfix: `sudo systemctl restart postfix`


### Install Betterbird

Thunderbird doesn't support Movemail, Betterbird is well better for this test.

https://www.betterbird.eu/

https://www.betterbird.eu/downloads/index.php

Download the tar archive and extract it: `tar -xvf betterbird-<VERSION>.en-US.linux-x86_64.tar.bz2`

cd in the betterbird directory and start the mail client with: `./betterbird`

### Configure Betterbird

When you first run betterbird it will ask you to connect with an account, just skip that part. You won't use this in this case.

On the settings panel click on "Account Actions" then click on "Add Movemail Account..."

- Specify your name: the one you enter previously during the Catch-all Addresse configuration, of course.
	- Your account will be: `<your-user>`
	- The Email Address: `<your-user>@localhost`
- Click "Next" and enter the name of the Account, for example "Test Account"
- Then click on Next and review the installation and click on "Finish"

In "Settings" click on "Account Settings" at the bottom of the left panel.

Then on the new tab, configure the "Outgoing Server (SMTP)":
- Add a new server
	- Description: `Localhost Postfix Server`
	- Server Name: `localhost`
	- Port: `25`
	- Connection security: `None`
	- Authentication method: `Password, transmitted insecurely`
	- User Name: `<your-user>@localhost`

*The authentication is just for the test, you will not use it for something else, right?*

If nothing happen, and Betterdird show this Alert message: "Unable to locate mail spool file."

There is one last step need to be done.

Remember to use your Unix account for all the configuration.

#### Test the correct installation of the Catch-all address

Send an email to `<your-user>@localhost` address.

Click on "Get email" and check if you get the email in your "Inbox".

## Gophish

First get the Docker from the Hub: `docker pull gophish/gophish:latest`

Start the containor with the following command:
`docker run -it --rm --network host <container image ID>`

You can get the container image id with this command: `docker images`

Watch the log when you run the container, this informations are important:
- The URL for the admin server: https://0.0.0.0:3333/
- And the generated password for the Admin user

At the first connection Gophish server ask you to change the password, change it to something you will remember. For this time at least.

**Reminder: the more realistic the campaign, the better the results will be.**

### Sending Profiles

Go to the 'Sending Profiles' and changes the parameter to match the postfix configuration:
- Name: `Local SMTP`
- Interface Type: `SMTP`
- SMTP From: this is the address used for sending email `<your user>@localhost.com`
- Host: `localhost.com:25`
- Username: `<your user>`
- Password: `<your password>`
- Ignore Certificate Errors: let's it at true

Next, click on "Send Test Email", normally if you don't have any problem it will send a test email to any address you will provide to the @localhost domain.

It will ask you for:
- First name
- Last name
- Email adress: `<first name>@localhost.com`
- Position

The Email is the mandatory information for this test, the others are just for the database.

Now send the test mail.

When you return to Betterbird and click on "Get Email", you have the "Default Email from Gophish" email in your Inbox.

Save the sending profiles.

Let's continue to configure the campaign.

### Landing page:

This is the web page view by the user once he click on the malicious link. It is write in HTML.

Go to this website or search on your favorite search engine a login page.
Or ask your assistant to generate HTML page with a form.

https://www.w3schools.com/howto/tryit.asp?filename=tryhow_css_login_form

*Don't take login page with online dependencies, prefer to take a page with all the code needed inside it.*

https://medium.com/@shopinson/how-to-create-a-login-form-w3schools-vs-bootstrap-6e8877f793af

Give a name to your page, and paste the HTML code you want to use. You can use whatever you want for this, if you already have the code needed.

Click on:
- Capture Submitted Data
- Capture Passwords

It will capture and store in the database the information you need for the success of your campaign.

You can add a redirection page, it is used to get more realism for the victim. For the test locally you can paste the URL you want. I personally use this one: https://www.youtube.com/watch?v=dQw4w9WgXcQ

Save your landing page.

### Email templates:

The Email template is the one used to deceive the victim to click on your link and to give the information.

Search again for an email template or just copy an email from your personal inbox.

https://github.com/criggs626/PhishingTemplates/blob/master/emails/Upgrade%20Webmail.html

Provide a name for this one.

You can import one mail if you already have one, with the "Import Email" button.

For the "Envelope Sender" add the sender you want to use: `<your sender>@localhost.com`

Give a Subject, something realistic even if this is a local test.

Add the HTML code in the new email template, and save it.

There is some variables available in Gophish, for the template and the landing pages.
Here some that can be useful:
- `{{.FirstName}}` :  first name of the user;
- `{{.URL}}` :  the URL use in the campaign;
- `{{.Email}}` :  the actual email used.

Click on "Save Template".

### Users & Groups

You will need people, email address to send your email. You can add it with the "Users & Groups" section.

Add a new group:
- Give it a name
- You can import a CSV Template if you have one or one you craft for it
- Save your changes at the end

### Campaign:

This is the actual campaign to tell people about the good news you have for them.

Create a campaign with clicking on the Campaigns > New Campaign. Then complete the information:
- Add a Name;
- Select the email template;
- Select the Landing Page;
- Specify the URL: http://127.0.0.1
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

**Go further:**

Try to use Let's encrypt certificate:

https://www.n00py.io/2017/09/phishing-with-gophish-and-letsencrypt/

Use Gmail in the **Sending Profile**:

https://hailbytes.com/how-to-setup-gmail-smtp-on-gophish/

*Worked in May 2024*

Use an attachment to deliver a payload.

You can use an Apache2 web server with Gophish and put a malicious file waiting to be downloaded by the email user.

##### Troubleshoot

Add apt-apt-repository, with apt.
- Correct the python error: https://askubuntu.com/questions/1480616/adding-opencpn-repository-attributeerror-nonetype-object-has-no-attribute

Postfix installation: https://gist.github.com/raelgc/6031274

https://hailbytes.com/how-to-setup-gmail-smtp-on-gophish/
Add apt-repository, with apt.
- Correct the python error: https://askubuntu.com/questions/1480616/adding-opencpn-repository-attributeerror-nonetype-object-has-no-attribute
