## JSON web Token ( JWT ) signing and verifying logic implementation
JWT essentially contains two methods

 - Sign: The method takes the payload and signs it with the secret stored at the server side
 - Verify: When a user tries to access a protected resource, he hits a server endpoint using a JWT, the server decodes the JWT, and extracts the payload. Using the payload and the secret stored at the server it creates a Test signature. If the Test signature is equal to the signature that is in the JWT, the user is **valid.**

> So, Tried to implement these features using Node and Typescript.
