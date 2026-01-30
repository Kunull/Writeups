> Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

&nbsp;

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/user-attachments/assets/7b4d5362-6a53-480d-a4fd-248fb7869a05?raw=1)
</figure>

```
>> start
```

Let's check the source code for the logic.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/user-attachments/assets/16730aff-eaf0-4ec6-a2a1-bd2218a65279?raw=1)
</figure>

## main.js

Visiting `main.js`, we can see the following code:

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/user-attachments/assets/a198025a-07cf-414c-b55d-00e5872b1f4c?raw=1)
</figure>

Scrolling back up, we can see that the `playerWon()` function has been imported from `game.js`.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/user-attachments/assets/681ec686-a002-42f3-8caa-e28cc7a962f7?raw=1)
</figure>

## game.js

Let's checkout `game.js`.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/user-attachments/assets/31b01f37-703d-491a-acb6-247f2151f814?raw=1)
</figure>

So, the `playerWon()` function simply outputs the `GAME_WON` string, which is imported from `commands.js`.

## commands.js

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/user-attachments/assets/b7143096-9573-4810-853f-8d137f7ed87e?raw=1)
</figure>

So far, we have found the string that gets outputted when we win the game, however, we have not found the logic that allows us to win.

## Network tab

Let's check out the network tab.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/user-attachments/assets/f5c6b41c-b232-4f21-b25b-02b4b35b30f5?raw=1)
</figure>

We can see a request is being sent to the `/options` endpoint.
Let's check out the response.

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/user-attachments/assets/3312fbf2-dfee-4a76-8daa-5e6ea3d0d7e8?raw=1)
</figure>

Looks like there is a secret command that we can provide.
Let's try it.

```
Blip-blop, in a pickle with a hiccup! Shmiggity-shmack
```

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/user-attachments/assets/6ac6dadd-3a63-4487-8aa0-780ebed82e1b?raw=1)
</figure>

## Flag

```
HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}
```
