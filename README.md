# Techie-Foodies-Hackathon-Repo
Repository of the Techie Foodies team for unstop online hackathon

Name of the project: CodeVigil

Problem Statement:
  OWASP Vulnerability Scanner: Create a simple web-app scanner that checks for OWASP Top 10 issues. For example, the tool can
  Analyze HTML/JS code snippets for common flaws (like missing input sanitization or open CORS) and flag them. 
  This project teaches secure coding practices by having students actively look for “Broken Access Control,” “Injections,” etc. – 
  exactly the risks highlighted in the OWASP Top 10 – using only open-source libraries.

The Implementation:
  The scanner functions on javascript.Its Interface is managed by a html file with required functionalities.
  
  The site consists of examples of the possible attack strategies in the form of code snippets as a way to give the user an understanding of the process.
  
  It also provides sanitization recommendations to remove the potentially malicious parts of the code snippet
  
  The pinpointing of the possible malicious parts is highlighted by an open source library called ESlint
  
  The recommendations to “sanitize”  the code is implemented by an open source library called DOMPurify.The JavaScript framework used is Node js.

  Instructions to Build the Project:
    In root folder of the project(hackathon_scanner)
    Run the commands:

      sudo apt install nodejs npm build-essential


      npm init -y # The -y flag accepts all default values


      npm install express cheerio eslint dompurify


      npm install body-parser


      npm install jsdom

To Run the project,use the command: node app.js
This should output CodeVigil server listening at http://localhost:3000
One can then visit this url to use the site

Team Members	

Ayaan Jilani-Team Lead
Moin Bhurani
Mohammed Shayanuddin 
Usman Ansari

Mentor-Ravi Theja Reddy







