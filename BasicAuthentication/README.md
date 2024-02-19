# Basic HTTP Authentication method
In this method username and password sent over a request after base64 encoding. the overall Authorization header token evaluated as follows:

```
Authorization: Basic base64(username + ":" + password)
```

In this method the authentication flow follows as below.

<img src="./images/basicAuthFlow.jpg"/>

1) User tries to visit a protected URL or resource.
2) Client sends the request to the server.
3) Server checks whether the ```Authorization``` header is present or not. follows the next step if present. else follows step 6.
4) Server decodes the header and checks the username and password in it's database. if the user found, then follows the next step. else follow step 6.
5) Server serves the requested resource and flow ends.
6) Server sets ```WWW-Authenticate``` header value to ```Basic realm="restricted", charset="UTF-8"``` and responds with 401 Unauthorized status.
7) After receiving the response, client automatically prompts the user to enter their username and password. on submit flow continues from step 2.

In basic authentication, if user wants to logout, he/she must close the tab or window of the client. it is not possible to logout a user programatically as the client persists basic authorization header for every request until exit.