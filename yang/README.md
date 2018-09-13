# Deckard Configuration Generator

[resolvers-yang](https://gitlab.labs.nic.cz/labs/resolvers-yang) package is needed

Generator for Deckard is also located in `resolvers-yang` repository in `examples/deckard/` directory. 

As you can see in `deckard-data.json` or `yanglib-deckard.json` Data Model for Deckard extends the resolvers common model by yang-module `cznic-deckard`. This module allows attach the path to `.rpl` file and add its contents into the generated configuration file.

## Usage
1. [Clone and install](https://gitlab.labs.nic.cz/labs/resolvers-yang) resolvers-yang package and other dependencies
 
    ```
    $ pip install -r requirements.txt
    ```

1. Go to `deckard/yang` directory
1. Edit `deckard-data.json`
1. Run `deckard_confgen.py` script with path to your editedJson.

```bash
$ cd yang
$ python deckar_confgen.py deckard-data.json
```
Configuration files `unbound.rpl` and `kresd.conf` will be created in local files. Files will be generated in the `yang` folder.

PS: In the script code you can edit paths where configuration files will be created.
