# appsec-project

## Description

Hello, welcome to the b1d0ws appsec project!

The goal of this repository is to accompany the AppSec project featured on my Hashnode blog. You can find the first chapter [here](https://b1d0ws.hashnode.dev/appsec-project-chapter-1-manually-fixing-vulnerabilities).

In this project, we will identify and manually fix the following vulnerabilities present in the application:

* Lack of Authentication
* Arbitrary File Upload and Path Traversal
* XSS
* CSRF
* Weak Password Reset Token Generation
* IDOR
* Privilege Escalation
* SQL Injection
* SSTI
* SSRF

Additionally, we'll enhance the app’s security posture by following best coding practices, integrating SAST tools, and implementing containerization.

<br>

### Branches

Main – This branch contains the vulnerable version of the application and serves as the starting point of our project.  

Fixing – This branch addresses the vulnerabilities identified up to the end of Chapter 2.  

Improvements – This branch is used in Chapter 3 to implement various security enhancements that improve the overall security of the web application.  

SAST – This branch contains our SAST tools tests, GitHub Action integration, containerization, and marks the conclusion of the project.

<br>

### Cloning the App

You can clone the app using Docker. The vulnerable image corresponds to the main branch, while the latest image reflects the final version of the project.
```
# This is the recommended image if you're starting the project now
docker pull bido/appsec-project:vulnerable

docker pull bido/appsec-project:latest
```

And run it:
```
docker container run -d -p 5000:5000 bido/appsec-project:vulnerable
```

Or with git.
```
git clone https://github.com/b1d0ws/appsec-project.git
cd appsec-project

# Specific branch
git clone https://github.com/b1d0ws/appsec-project.git -b sast
```

<br>

### Usage

To get started with Application Security, you can either read through the articles and follow along or challenge yourself by identifying and fixing the vulnerabilities on your own.

The default administrator user is `teste@gmail.com` with the password `teste123`, which can be found in the main branch database.

If you want to add more adminsitrator users, you'll need to manually insert them into the database.

An easy way to create an administrator is to first create a regular user in the app and then update their role to admin with the following query in SQLite3:

```
sqlite3 .\instance\database.db
UPDATE user SET role = 'administrator' WHERE id = 1;
```
