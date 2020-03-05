# Database

OpenPGP CA uses an sqlite database to keep all of its state.

There are 3 ways of configuring while database file is user:

1.  the most common way is to set the `OPENPGP_CA_DB` environment variable
2.  the optional parameter "-d" overrides all other settings and sets the database file
3.  a `.env` file can set the environment variable `DATABASE_URL` "in the style of the ruby dotenv gem"

If the configured database file doesn't exist, it will get created implicitly.
