# Hash Generator
Hash Generator is vulnerable web application. Your goal is to exploit it and get the flag.
# How to use
Compile and run it locally:
```
go build
USER_PWD="user_password_here" SECRET_KEY="your_secret_key_here" FLAG="flag{your_flag_here}" ./hash-generator
```
or use docker:
```
docker build -t hash-generator
docker run -d -e USER_PWD="user_password_here" -e SECRET_KEY="your_secret_key_here" -e FLAG="flag{your_flag_here}" -p 8000:8000 hash-generator
```
Open the browser on localhost:8000 and login with "user@example.com" and password "user_password_here"