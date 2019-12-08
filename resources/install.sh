#!/bin/bash

if ! [[ -f ~/.bash_completion ]]; then
	echo '[+] Creating local completion script ~/.bash_completion'
	cp ./bash_completion ~/.bash_completion
fi

if ! [[ -d ~/.bash_completion.d ]]; then
	echo '[+] Creating local completion folder ~/.bash_completion.d'
	mkdir ~/.bash_completion.d
fi

if ! [[ -f ~/.bash_completion.d/rmg ]]; then
	echo '[+] Creating rmg completion script ~/.bash_completion.d/rmg'
	cp ./bash_completion.d/rmg ~/.bash_completion.d/rmg
fi

if ! [[ -d ~/.local/bin ]]; then
	echo '[+] Creating local bin folder ~/.local/bin'
	mkdir -p ~/.local/bin
fi

if ! [[ -f ~/.local/bin/rmg ]]; then
	echo '[+] Creating symlink for rmg'
	path="$(dirname $(pwd))/target/rmg.jar"

	if ! [[ -f $path ]]; then
		echo "[-] rmg.jar not found at $path"
	else
		chmod +x $path
		ln -s $path ~/.local/bin/rmg
	fi
fi
