# Homework 5

Homework 5 due *Tuesday* October 7, 9 pm ET: 

**You will work alone on this assignment.** TFs will be able to help if you need assistance with Python or Git, but please start the assignment early.

## 5.1: Set up Linear (10 points)

- Accept the email invitation you'll receive and join your project team. To help us grade accurately, please use the email address we obtained from the registrar—the exact email the invitation was sent to.
- Review the Start Guide in [Linear](https://linear.app/docs/start-guide).
- Create two Linear tasks for yourself to complete 5.2 and 5.3 below. Give each of them an "HW5" label.

## 5.2: Try to Use Generative AI to Build a SQL Injection Attack (15 points)

In 2025-10-02's lecture, we showed the following vulnerable SQL code as a bad implementation of Homework 4's county_data endpoint, which is currently running on https://cat-hw4.vercel.app/county_data. (If you look at it with a browser, it will fail because a browser sends a GET, not the required POST request.) 

```python
sql = f"select * from county_health_rankings where county = '{county}' and state = '{state}' and measure_name = '{measure_name}'"
cursor = conn.execute(sql)
```

Create a file called `test.json` that has the following data:

```json
{"zip":"84601","measure_name":"Adult obesity"}
```

Use it with curl to test the endpoint:

```json
$ curl -X POST https://cat-hw4.vercel.app/county_data -H "Content-Type: application/json" -d @test.json

[{"confidence_interval_lower_bound":"0.17","confidence_interval_upper_bound":"0.22","county":"Utah County", ...
```

Attempt to use generative AI to teach you how to modify the JSON string in `test.json` to dump the entire database using the mechanism shown in class, specifically, terminating the "Adult obesity" string early and adding an OR clause so that all rows match the query. Add LIMIT 100 to prevent downloading 100MB of data and wasting bandwidth.

Put the malicious JSON in `attack.json`. Put your prompts only (no output) in `prompts.txt`.

In your `README.md` file, include a section on the model names you attempted the prompts on. If you had resistance from any model to help you complete an attack, discuss what guardrails were in place, and how you got around them (or weren't able to.)

## Use Generative AI to Prototype a Simple Penetration Tester (25 points)

Download the hw5_server repository from https://github.com/cs1060f25/hw5_server Links to an external site.. When you are ready to test your program, run `ssh_server.py` and `http_server.py` to create vulnerable services.

Create a new, private GitHub repository in the cs1060f25 organization. It should be in the format `<username>-hw5`, as before. You do not need to fork or use the public hw5_server repository template for your homework. If you decide it's easier than making a new one, you can—but use it as a template.

Using Generative AI, build a Python program called `vulnerability_scanner.py`:
- Use the nmap tool (typically, the python-nmap library) to scan open TCP ports on your localhost (127.0.0.1). Ignore ports numbered 9000 and higher.
- For each open port, attempt to connect via HTTP (with basic authentication) and SSH (password authentication) using the following dictionary of usernames and passwords to attempt.

    ```
    credentials = {
        'admin': 'admin',
        'root': 'abc123',
        'skroob': '12345'
    }
    ```

- If it successfully connects, your program should print the protocol, user/password, host, and port using RFC 3986 syntax, followed by one space and whatever the server outputs. (Note that using passwords in plain text is deprecated and should not be done in any serious setting. Links to an external site.) The supplied servers currently output the string "success." Our grading scripts will output other strings. Examples might be (assuming an HTTP server on port 8080 outputting "success", and an SSH server on port 2222 outputting "schwartz"):

    ```
    http://admin:admin@127.0.0.1:8080 success
    ssh://skroob:12345@127.0.0.1:2222 schwartz 
    ```

- Your program should print nothing else. If it finds no vulnerabilities, it should output nothing.
- **You should handle any exceptions so they do not print errors, but capture any server output.**
- The systems are intentionally brittle and not fully compliant. Never assume you're connecting to 100% bug-free systems.
- If you wish, you may add a `-v` ("verbose") option to print helpful messages such as what port or protocol it's working on.

**You should work alone on this assignment.** You may use any generative AI or other online resources you like, excluding any materials by or discussions with other students in this course (and of course you may not pay other people to do it for you.) You may ask TFs for help. You must indicate in your code files where you obtained any code, whether from GenAI, StackOverflow, your friend's dog.

## Submission requirements:

- In Canvas, submit a link to your private GitHub repository in the cs1060f25 organization. It should be in the format <username>-hw5, as before.
- You do not need to deploy your program anywhere.
- Your repository must have the following files:
    - `./attack.json`
    - `./test.json`
    - `./prompts.txt`
    - `./vulnerability_scanner.py`
    - `./requirements.txt` (if needed for your scanner)
    - `./README.md`
    - `./.gitignore`
- Your `.gitignore` file may be simple, preventing caches from being checked in, or boilerplate. See for example [this discussion](https://stackoverflow.com/questions/3719243/best-practices-for-adding-gitignore-file-for-python-projects) or
https://github.com/github/gitignore/blob/main/Python.gitignore