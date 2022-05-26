
<h1 align="center">
  <br>
  The Crypt (WORK IN PROGRESS)
  <br>
</h1>

![TheCrypt](readme/crypt.jpg)

<h4 align="center">A minimal Password Manager / Generator</h4>



<p align="center">
  <a href="#key-features">Important Notes </a> •
  <a href="#key-features">Key Features</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#how-to-use">To Do</a> •
  <a href="#credits">Credits</a> •
  <a href="#license">License</a>
</p>

## Important Notes

This python project is intended to explore and understand how the cryptodome library works or at least one possible 
approach. The project does not pretend to have a nice to see, pretty shining interface, I'm definitely not a Tkinter 
expert, as a matter of fact I hate it :D but I wanted get at least a decent graphical interface without printing 
output in terminal which would have been less professional in my opinion. Feel free to improve the interface as well 
give me inputs and suggestion on how to improve the security further

## Key Features

* Minimal and ugly graphical interface
* Data's storage on local sqlite DB
* Strong password generation
* Password's strength check (complexity + test against common dict)


## How To Use

First of all, you will need to generate a Salt as well a master password hash. 

```bash
python pwd_master_hash_gen.py
```

you will get printed out your salt as well the hash based on your master password input. You have to copy and paste salt and hash into
the pwd_master.py, respectively b='' and master_password_hash = "" 

you are now ready to run the main.py. A TheCrypt.db file will be created, keep it safe even if passwords are encrypted before be written into the db of course

> **Note**
> Loosing the first generated salt and/or master password hash will transform your database in a garbage of useless bytes unless you are 
> able to crack it ... all the best

## To Do


## Credits

This software takes inspiration from:

#- [python-sql-password-manager](https://github.com/collinsmc23/python-sql-password-manager)


## License

MIT

---
> GitHub [@cryptoshepherd](https://github.com/) &nbsp;&middot;&nbsp;
> Twitter [@the_lello](https://twitter.com/)

