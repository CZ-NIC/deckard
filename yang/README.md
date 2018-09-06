## Run Test 

`resolvers-yang` package is needed

```
$ pip install -r requirements.txt
```
Edit `deckard-data.json`.

Generate deckard configuration files
```
$ cd yang
$ python3 generate_conf.py deckard-data.json
```

Files will be generated in the `yang` folder.