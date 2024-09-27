# OpenCVE - Opensource Vulnerability Management Platform

OpenCVE is an open-source platform designed to help organizations and cybersecurity professionals monitor, track, and manage vulnerabilities (CVEs) from the global CVE database in real time.

The interesting part is to received an email when a new CVE appeared on your project.

OpenCVE is completely open source, it means you can clone the project and use it on your own infrastructure.

They offer the opportunity to test the platform:

https://app.opencve.io/cve/

### Pricing

OpenCVE have 4 offers:
- Free
- Starter
- Pro
- Enterprise

I will try the free offer. This is just for personal use and development.

The free content:
- 1 project/user/notification
- 5 subscription
- 1 month of report retention
- API calls 60/hour
- And email notification

## Create a free account

You can create a free account for the SaaS version on the main web page. When you click on "GET STARTED" on the upper right of the page, you have a form. Fill in the information needed.

Next, validate your email address and that's it, the sign up process is finished.

Finally, I sign in the platform. 

## Configuration

The main page contain a left panel.

First, create an organization. You need to have one for the vulnerability management.

Next, you need to configure a project. Go to "Project" > "Manage Projects" and click on "Create a new project?"

Give a name to the project, the description is optional (but recommended if you a lot) and save it.

After that you're on the project page, there is the dashboard with other tab and the "Subscriptions" one.

When it is done, you can configure some tags, here I create a few of them:
- CRITICAL
- Linux
- Microsoft

Maybe later I will be more inspired.

In order to receive the email, a subscription is needed. Remember with the free account the limitation is set to 5.

Go to the "Vendors & Products" on the left pane, you will see two pane under a search bar.

For example search for: "microsoft"

The result content: one vendor and 73 products.

Search your own vendor and product, I tried some protocol, anti malware, EDR, etc.

When you return to your project, it is automatically populated with CVEs.

You can also see the "Weakness" on the left pane, there are a lot of CWE available to be read.

You can manage the subscriptions in the tab of the same name.

Lastly but not the less important, in your project got to "Notification".

Now add:
- Name: whatever you want
- email: a valid email

Configure the Alert settings you want (keep in mind if the severity is too low or to large there a risk of flooding).

Now the notifications are activate.

The free account limit the notification to only one email address.

## OpenCVE API

The most interesting part of this kind of resource is the Rest API. With that you can use it and integrate it to you own project.

I ask to ChatGPT a sample of code for a basic use:
```python
import requests

# Configuration
api_token = 'YOUR_API_TOKEN'
headers = {'Authorization': f'Token {api_token}'}

# Retrieve recent CVEs
response = requests.get('https://www.opencve.io/api/cve/', headers=headers)

# Checking request success
if response.status_code == 200:
    cves = response.json()
    for cve in cves:
        print(f"CVE ID: {cve['cve_id']}, Score: {cve['cvss']}")
else:
    print(f"Erreur: {response.status_code}")

```

So, like always the code from the know LLM need to be check first. I leave it here for another of my own project, I will test it later. Without promises.

Of course it work with bash, and even with Powershell if you are not lucky.

https://docs.opencve.io/v1/api/

### Keywords reminder

| Acronym | Description                          |
| ------- | ------------------------------------ |
| CPE     | Common Platform Enumeration          |
| CVE     | Common Vulnerabilities and Exposures |
| CVSS    | Common Vulnerability Scoring System  |
| CWE     | Common Weakness Enumeration          |

### URL Links:

https://www.opencve.io/
https://docs.opencve.io/
https://app.opencve.io/cve/
https://github.com/opencve/opencve