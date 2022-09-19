# scriptie-demo
A demo of my proposed SSI Presentation Exchange with Verifier Authorization for my master thesis

To run the program, the following python libraries are required:

<code>pycryptodome</code>

<code>requests</code>

<code>json</code>

<code>pickle</code>

<code>threading</code>

All of these can be installed via <code>pip</code>

Once you've installed all necessary packages, you can run the run the demo by entering the following commands in your command line:

```
cd src
python3 main.py
```

This demo models two (and a half) use cases, based on the Use Cases defined in Section 2.2 of my thesis.
The first use case is based on the notary use case (Section 2.2.2) and models an interaction between an executor who has been authorized to access the bank account of a recently deceased person in their will and the bank of the deceased, in which the executor wants to gain access to the deceased's bank account.
The second use case models the application form for home aid example from Anciaux et al. (2013). In both these use cases, the verifier is acting benevolently, i.e. they only request attributes that they obtained permission for from the wallet.
The demo also includes a last use case, in which the verifier is acting malevolently. In this case, they are requesting credit card data from the user.
