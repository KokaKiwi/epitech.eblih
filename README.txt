
How to install EBLIH (Epitech Binary Low-Interface for Humans)
==============================================================

Type in your shell:

    git clone git://git.kokakiwi.net/epitech/eblih.git
    cd eblih
    sudo ./install.sh
    bliny bootstrap # Only if you want to automatically create and upload a SSH key.

If you don't want to install tools in /usr/local, add 'PREFIX=/usr' between 'sudo' and './install.sh'

If you already have a SSH key, but not named "~/.ssh/id_rsa", don't forget to add it to your SSH agent (ssh-add or other) ;)
But, in general, it's better to have a key at this path because it's where most of SSH-based programs will looking for a key. :)

How to use EBLIH
================

Create a repository and init it
-------------------------------

Create it and clone it in the current directory:

    bliny create <repository name>
    cd <repository name>

Create it and clone it in the path specified:

    bliny create <repository name> <path>
    cd <path>

Import an existing repository
-------------------

    bliny import <repository name> [path]
    cd <path specified or repository name>
