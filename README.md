# dcc-dashboard
The Core's web dashboard, including a faceted file browser.

This iteration of the File Browser uses the web API from https://github.com/BD2KGenomics/dcc-dashboard-service.

## Set up the web API
Follow the directions on https://github.com/BD2KGenomics/dcc-dashboard-service.
   
## Start Dashboard server for Github OAuth

In this setup, the UCSC Dashboard server is configured to allow OAuth support via Github, allowing users to assure that *they are who they say they are*.

You should have a registered [Github application](https://github.com/settings/developers), specifying a particular **homepage URL** (e.g., *http://localhost:8000*) and **callback URL** (e.g., *http://localhost:8000/callback*), and obtaining a particular **client ID** and **client secret**.

Specify the client ID and client secret:

```
# ..via Python..
python dashboard.py abc abc

# ..or Docker..
docker run --network host --env CLIENT_ID=abc --env CLIENT_SECRET=abc ucsc-dashboard
```

## Start Dashboard, via EC2 instance
Launch a new EC2 instance, and SSH to it.  Make sure it has security group clearance of TCP port 8000.

Run these commands in the EC2 instance.

Docker needs to be installed on it:

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install docker
```

Then we need to download the source code, and build a Docker image:

```
git clone http://github.com/dkucsc/dcc-dashboard
cd dcc-dashboard
git checkout feature/auth
docker build -t ucsc-dashboard .
```
