---
custom_edit_url: null
---

## level 1.0

> Reverse engineer this challenge to find the correct license key.

Let's provide an input which we can easily spot such as `abcde`.

```
Initial input:

        61 62 63 64 65 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        61 62 63 64 65 

```

We can see that the program didn't actually mangle our input.

The program also tells us what the expected result is.

```
Expected result:

        6b 78 71 68 73 <------ kxqhs
```

Since there is no mangling performed we can just input `kxqhs` which is the ASCII representation of the expected input.

&nbsp;

## level 1.1

In this level the program does not print out the expected input.

On examining the .data section, we can see that the expected input is "hgsaa".

&nbsp;

## level 2.0

> This challenge is now mangling your input using the `swap` mangler for indexes `3` and `4`.

We will provide the same initial input as before.

```
Initial input:

        61 62 63 64 65 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `4`.

This mangled your input, resulting in:

        61 62 63 65 64 

The mangling is done! The resulting bytes will be used for the final comparison.
```

We can see that the fourth and fifth characters have been flipped. Let's keep this in mind for when we provide the actual key.

Looking at the expected result tells us what the actual key would look like after mangling is done.

```
Expected result:

        6a 6b 76 74 66 <------ jkvtf
```

Remember that the fourth and fifth bytes are flipped, so `jkvft` is actual the key.

&nbsp;

## level 3.0

> This challenge is now mangling your input using the `reverse` mangler.

This level also mangles our input using a reverse mangler.

```
Initial input:

        61 62 63 64 65 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

        65 64 63 62 61 

The mangling is done! The resulting bytes will be used for the final comparison.
```

As we can see, the order of our input bytes have been flipped, i.e. the LSB is now MSB and vice-versa.

Let's look at the expected result after mangling.

```
Expected result:

        65 78 63 73 64 <------ excsd
```

The expected result after reversing is `excsd`, therefore the key `dscxe` is what we have to provide as user input.

&nbsp;

## level 4.0

> This challenge is now mangling your input using the `sort` mangler.

This one is similar to level 1.0.

```
Initial input:

        61 62 63 64 65 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

        61 62 63 64 65 

The mangling is done! The resulting bytes will be used for the final comparison.
```

As we can see our input hasn't actually been sorted.

We simply have to provide the expected result as the key.

```
Expected result:

        66 67 67 6b 79 <---- fggky
```

Our key will be `fggky`.

&nbsp;

## level 5.0

```
Initial input: 31 32 33 34 35
Mangled input: 34 37 36 31 30

Expected input: 67 69 60 61 60 <---- gi`a`
```

Each character is mapped to some other character .

If we provide the expected characters, we can see what characters they are mapped to.

```
Initial input: 67 69 60 61 60 <---- gi`a`
Mangled input: 62 6c 65 64 65 <---- blede

Expected input: 67 69 60 61 60 <---- gi`a`
```

So we must provide the string to which expected input is mapped (i.e. blede).
