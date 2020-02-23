Breaking one-time-pad with key reuse.

Pairs of XORed cipher texts would be the XOR of their respective plain texts:

```
ctext1 ^ ctext2 == ptext1 ^ ptext2
```

Next, we try to find common phrases in the cipher text. We could assume that " the " occurs in ctext at in some position `pos`, then we see if assuming that, ptext2 would look like English text.

We check if the following should look like English:

```
crib = " the "
crib ^ ptext1[pos:len(" the ")] ^ ptext2[pos:len(" the ")]
```

If not, the guess is probably wrong.

We could make these guesses for all pairs of available cipher texts.

If the guess looks right, just work backwards from the plain text to get the key.
